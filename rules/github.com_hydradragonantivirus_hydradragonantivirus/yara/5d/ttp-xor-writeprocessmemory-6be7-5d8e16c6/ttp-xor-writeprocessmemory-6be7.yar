rule TTP_XOR_WriteProcessMemory_6be7 {
  strings:
    $key_6be7 = { 3c 95 [2] 0e b7 [2] 08 82 [2] 26 82 [2] 19 9e }

  condition:
    any of them
}