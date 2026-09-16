rule TTP_XOR_WriteProcessMemory_7110 {
  strings:
    $key_7110 = { 26 62 [2] 14 40 [2] 12 75 [2] 3c 75 [2] 03 69 }

  condition:
    any of them
}