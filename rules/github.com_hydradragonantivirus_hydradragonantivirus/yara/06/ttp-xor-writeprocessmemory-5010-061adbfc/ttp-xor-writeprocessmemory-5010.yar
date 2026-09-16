rule TTP_XOR_WriteProcessMemory_5010 {
  strings:
    $key_5010 = { 07 62 [2] 35 40 [2] 33 75 [2] 1d 75 [2] 22 69 }

  condition:
    any of them
}