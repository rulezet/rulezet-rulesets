rule TTP_XOR_WriteProcessMemory_1754 {
  strings:
    $key_1754 = { 40 26 [2] 72 04 [2] 74 31 [2] 5a 31 [2] 65 2d }

  condition:
    any of them
}