rule TTP_XOR_WriteProcessMemory_b89c {
  strings:
    $key_b89c = { ef ee [2] dd cc [2] db f9 [2] f5 f9 [2] ca e5 }

  condition:
    any of them
}