rule TTP_XOR_WriteProcessMemory_b454 {
  strings:
    $key_b454 = { e3 26 [2] d1 04 [2] d7 31 [2] f9 31 [2] c6 2d }

  condition:
    any of them
}