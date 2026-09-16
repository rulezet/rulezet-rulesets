rule TTP_XOR_WriteProcessMemory_5610 {
  strings:
    $key_5610 = { 01 62 [2] 33 40 [2] 35 75 [2] 1b 75 [2] 24 69 }

  condition:
    any of them
}