rule TTP_XOR_WriteProcessMemory_bdd8 {
  strings:
    $key_bdd8 = { ea aa [2] d8 88 [2] de bd [2] f0 bd [2] cf a1 }

  condition:
    any of them
}