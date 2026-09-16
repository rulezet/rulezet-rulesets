rule TTP_XOR_WriteProcessMemory_6324 {
  strings:
    $key_6324 = { 34 56 [2] 06 74 [2] 00 41 [2] 2e 41 [2] 11 5d }

  condition:
    any of them
}