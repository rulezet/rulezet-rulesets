rule TTP_XOR_WriteProcessMemory_4310 {
  strings:
    $key_4310 = { 14 62 [2] 26 40 [2] 20 75 [2] 0e 75 [2] 31 69 }

  condition:
    any of them
}