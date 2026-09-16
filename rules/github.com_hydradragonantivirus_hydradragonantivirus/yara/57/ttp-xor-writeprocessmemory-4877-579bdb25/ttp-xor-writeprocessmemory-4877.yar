rule TTP_XOR_WriteProcessMemory_4877 {
  strings:
    $key_4877 = { 1f 05 [2] 2d 27 [2] 2b 12 [2] 05 12 [2] 3a 0e }

  condition:
    any of them
}