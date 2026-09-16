rule TTP_XOR_WriteProcessMemory_4861 {
  strings:
    $key_4861 = { 1f 13 [2] 2d 31 [2] 2b 04 [2] 05 04 [2] 3a 18 }

  condition:
    any of them
}