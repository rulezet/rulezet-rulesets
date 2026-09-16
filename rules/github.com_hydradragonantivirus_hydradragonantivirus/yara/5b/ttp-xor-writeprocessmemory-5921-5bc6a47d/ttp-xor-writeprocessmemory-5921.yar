rule TTP_XOR_WriteProcessMemory_5921 {
  strings:
    $key_5921 = { 0e 53 [2] 3c 71 [2] 3a 44 [2] 14 44 [2] 2b 58 }

  condition:
    any of them
}