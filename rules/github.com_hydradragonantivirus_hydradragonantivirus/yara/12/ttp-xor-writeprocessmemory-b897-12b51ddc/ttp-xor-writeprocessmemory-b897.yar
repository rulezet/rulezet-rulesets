rule TTP_XOR_WriteProcessMemory_b897 {
  strings:
    $key_b897 = { ef e5 [2] dd c7 [2] db f2 [2] f5 f2 [2] ca ee }

  condition:
    any of them
}