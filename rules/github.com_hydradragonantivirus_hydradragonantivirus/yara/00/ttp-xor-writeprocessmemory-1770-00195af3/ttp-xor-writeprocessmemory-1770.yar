rule TTP_XOR_WriteProcessMemory_1770 {
  strings:
    $key_1770 = { 40 02 [2] 72 20 [2] 74 15 [2] 5a 15 [2] 65 09 }

  condition:
    any of them
}