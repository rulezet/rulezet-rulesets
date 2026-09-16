rule TTP_XOR_WriteProcessMemory_4851 {
  strings:
    $key_4851 = { 1f 23 [2] 2d 01 [2] 2b 34 [2] 05 34 [2] 3a 28 }

  condition:
    any of them
}