rule TTP_XOR_WriteProcessMemory_af9e {
  strings:
    $key_af9e = { f8 ec [2] ca ce [2] cc fb [2] e2 fb [2] dd e7 }

  condition:
    any of them
}