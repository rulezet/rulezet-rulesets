rule TTP_XOR_WriteProcessMemory_7151 {
  strings:
    $key_7151 = { 26 23 [2] 14 01 [2] 12 34 [2] 3c 34 [2] 03 28 }

  condition:
    any of them
}