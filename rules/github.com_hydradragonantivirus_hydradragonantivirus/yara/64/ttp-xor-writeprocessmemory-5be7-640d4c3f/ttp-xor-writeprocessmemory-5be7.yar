rule TTP_XOR_WriteProcessMemory_5be7 {
  strings:
    $key_5be7 = { 0c 95 [2] 3e b7 [2] 38 82 [2] 16 82 [2] 29 9e }

  condition:
    any of them
}