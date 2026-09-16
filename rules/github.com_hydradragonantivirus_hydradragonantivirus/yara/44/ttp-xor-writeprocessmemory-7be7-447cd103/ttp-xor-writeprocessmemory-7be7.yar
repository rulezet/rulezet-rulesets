rule TTP_XOR_WriteProcessMemory_7be7 {
  strings:
    $key_7be7 = { 2c 95 [2] 1e b7 [2] 18 82 [2] 36 82 [2] 09 9e }

  condition:
    any of them
}