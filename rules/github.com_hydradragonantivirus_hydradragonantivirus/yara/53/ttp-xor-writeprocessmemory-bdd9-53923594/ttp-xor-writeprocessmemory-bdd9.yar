rule TTP_XOR_WriteProcessMemory_bdd9 {
  strings:
    $key_bdd9 = { ea ab [2] d8 89 [2] de bc [2] f0 bc [2] cf a0 }

  condition:
    any of them
}