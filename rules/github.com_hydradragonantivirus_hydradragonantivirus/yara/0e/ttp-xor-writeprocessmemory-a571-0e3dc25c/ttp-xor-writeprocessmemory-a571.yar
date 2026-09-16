rule TTP_XOR_WriteProcessMemory_a571 {
  strings:
    $key_a571 = { f2 03 [2] c0 21 [2] c6 14 [2] e8 14 [2] d7 08 }

  condition:
    any of them
}