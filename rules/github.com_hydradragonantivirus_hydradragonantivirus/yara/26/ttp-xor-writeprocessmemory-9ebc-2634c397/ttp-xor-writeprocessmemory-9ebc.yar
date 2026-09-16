rule TTP_XOR_WriteProcessMemory_9ebc {
  strings:
    $key_9ebc = { c9 ce [2] fb ec [2] fd d9 [2] d3 d9 [2] ec c5 }

  condition:
    any of them
}