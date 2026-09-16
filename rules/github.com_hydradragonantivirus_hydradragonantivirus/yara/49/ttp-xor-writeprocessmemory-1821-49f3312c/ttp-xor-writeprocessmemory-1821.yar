rule TTP_XOR_WriteProcessMemory_1821 {
  strings:
    $key_1821 = { 4f 53 [2] 7d 71 [2] 7b 44 [2] 55 44 [2] 6a 58 }

  condition:
    any of them
}