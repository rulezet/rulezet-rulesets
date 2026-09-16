rule TTP_XOR_WriteProcessMemory_a554 {
  strings:
    $key_a554 = { f2 26 [2] c0 04 [2] c6 31 [2] e8 31 [2] d7 2d }

  condition:
    any of them
}