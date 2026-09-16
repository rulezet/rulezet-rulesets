rule TTP_XOR_WriteProcessMemory_aca4 {
  strings:
    $key_aca4 = { fb d6 [2] c9 f4 [2] cf c1 [2] e1 c1 [2] de dd }

  condition:
    any of them
}