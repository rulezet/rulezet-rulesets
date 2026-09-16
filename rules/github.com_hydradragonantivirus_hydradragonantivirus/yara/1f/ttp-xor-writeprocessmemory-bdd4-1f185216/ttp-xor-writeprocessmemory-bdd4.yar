rule TTP_XOR_WriteProcessMemory_bdd4 {
  strings:
    $key_bdd4 = { ea a6 [2] d8 84 [2] de b1 [2] f0 b1 [2] cf ad }

  condition:
    any of them
}