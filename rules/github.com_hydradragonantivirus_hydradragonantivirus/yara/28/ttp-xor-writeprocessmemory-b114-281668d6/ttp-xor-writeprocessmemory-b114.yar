rule TTP_XOR_WriteProcessMemory_b114 {
  strings:
    $key_b114 = { e6 66 [2] d4 44 [2] d2 71 [2] fc 71 [2] c3 6d }

  condition:
    any of them
}