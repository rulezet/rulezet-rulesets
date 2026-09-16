rule TTP_XOR_WriteProcessMemory_4860 {
  strings:
    $key_4860 = { 1f 12 [2] 2d 30 [2] 2b 05 [2] 05 05 [2] 3a 19 }

  condition:
    any of them
}