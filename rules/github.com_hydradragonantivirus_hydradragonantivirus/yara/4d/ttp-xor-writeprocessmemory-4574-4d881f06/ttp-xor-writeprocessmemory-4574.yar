rule TTP_XOR_WriteProcessMemory_4574 {
  strings:
    $key_4574 = { 12 06 [2] 20 24 [2] 26 11 [2] 08 11 [2] 37 0d }

  condition:
    any of them
}