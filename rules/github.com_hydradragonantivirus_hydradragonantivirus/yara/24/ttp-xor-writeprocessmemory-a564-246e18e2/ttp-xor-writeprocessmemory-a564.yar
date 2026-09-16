rule TTP_XOR_WriteProcessMemory_a564 {
  strings:
    $key_a564 = { f2 16 [2] c0 34 [2] c6 01 [2] e8 01 [2] d7 1d }

  condition:
    any of them
}