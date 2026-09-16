rule TTP_XOR_WriteProcessMemory_7810 {
  strings:
    $key_7810 = { 2f 62 [2] 1d 40 [2] 1b 75 [2] 35 75 [2] 0a 69 }

  condition:
    any of them
}