rule TTP_XOR_WriteProcessMemory_bddb {
  strings:
    $key_bddb = { ea a9 [2] d8 8b [2] de be [2] f0 be [2] cf a2 }

  condition:
    any of them
}