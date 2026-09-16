rule TTP_XOR_WriteProcessMemory_b893 {
  strings:
    $key_b893 = { ef e1 [2] dd c3 [2] db f6 [2] f5 f6 [2] ca ea }

  condition:
    any of them
}