rule TTP_XOR_WriteProcessMemory_2510 {
  strings:
    $key_2510 = { 72 62 [2] 40 40 [2] 46 75 [2] 68 75 [2] 57 69 }

  condition:
    any of them
}