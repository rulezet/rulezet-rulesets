rule TTP_XOR_WriteProcessMemory_4510 {
  strings:
    $key_4510 = { 12 62 [2] 20 40 [2] 26 75 [2] 08 75 [2] 37 69 }

  condition:
    any of them
}