rule TTP_XOR_WriteProcessMemory_5210 {
  strings:
    $key_5210 = { 05 62 [2] 37 40 [2] 31 75 [2] 1f 75 [2] 20 69 }

  condition:
    any of them
}