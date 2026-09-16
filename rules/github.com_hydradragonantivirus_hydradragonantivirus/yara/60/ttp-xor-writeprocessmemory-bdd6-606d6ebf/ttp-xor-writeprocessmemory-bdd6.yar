rule TTP_XOR_WriteProcessMemory_bdd6 {
  strings:
    $key_bdd6 = { ea a4 [2] d8 86 [2] de b3 [2] f0 b3 [2] cf af }

  condition:
    any of them
}