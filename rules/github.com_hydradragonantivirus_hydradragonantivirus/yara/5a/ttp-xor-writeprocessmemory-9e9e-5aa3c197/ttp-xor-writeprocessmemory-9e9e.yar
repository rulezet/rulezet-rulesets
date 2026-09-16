rule TTP_XOR_WriteProcessMemory_9e9e {
  strings:
    $key_9e9e = { c9 ec [2] fb ce [2] fd fb [2] d3 fb [2] ec e7 }

  condition:
    any of them
}