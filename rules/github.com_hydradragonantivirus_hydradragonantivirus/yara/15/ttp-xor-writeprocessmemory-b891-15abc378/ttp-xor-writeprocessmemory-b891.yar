rule TTP_XOR_WriteProcessMemory_b891 {
  strings:
    $key_b891 = { ef e3 [2] dd c1 [2] db f4 [2] f5 f4 [2] ca e8 }

  condition:
    any of them
}