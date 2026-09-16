rule TTP_XOR_WriteProcessMemory_bdd2 {
  strings:
    $key_bdd2 = { ea a0 [2] d8 82 [2] de b7 [2] f0 b7 [2] cf ab }

  condition:
    any of them
}