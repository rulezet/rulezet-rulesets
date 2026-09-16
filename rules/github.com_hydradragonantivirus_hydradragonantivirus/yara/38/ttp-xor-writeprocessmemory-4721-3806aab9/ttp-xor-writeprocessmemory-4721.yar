rule TTP_XOR_WriteProcessMemory_4721 {
  strings:
    $key_4721 = { 10 53 [2] 22 71 [2] 24 44 [2] 0a 44 [2] 35 58 }

  condition:
    any of them
}