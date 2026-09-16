rule TTP_XOR_WriteProcessMemory_4820 {
  strings:
    $key_4820 = { 1f 52 [2] 2d 70 [2] 2b 45 [2] 05 45 [2] 3a 59 }

  condition:
    any of them
}