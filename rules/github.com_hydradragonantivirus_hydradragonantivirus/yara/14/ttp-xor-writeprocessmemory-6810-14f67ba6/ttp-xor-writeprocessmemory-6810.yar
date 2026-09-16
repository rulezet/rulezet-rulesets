rule TTP_XOR_WriteProcessMemory_6810 {
  strings:
    $key_6810 = { 3f 62 [2] 0d 40 [2] 0b 75 [2] 25 75 [2] 1a 69 }

  condition:
    any of them
}