rule TTP_XOR_WriteProcessMemory_4840 {
  strings:
    $key_4840 = { 1f 32 [2] 2d 10 [2] 2b 25 [2] 05 25 [2] 3a 39 }

  condition:
    any of them
}