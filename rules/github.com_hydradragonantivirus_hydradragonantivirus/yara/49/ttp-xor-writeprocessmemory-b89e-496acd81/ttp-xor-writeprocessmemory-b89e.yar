rule TTP_XOR_WriteProcessMemory_b89e {
  strings:
    $key_b89e = { ef ec [2] dd ce [2] db fb [2] f5 fb [2] ca e7 }

  condition:
    any of them
}