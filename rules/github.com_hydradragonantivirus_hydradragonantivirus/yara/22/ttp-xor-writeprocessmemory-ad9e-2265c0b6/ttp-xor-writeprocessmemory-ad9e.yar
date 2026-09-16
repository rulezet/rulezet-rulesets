rule TTP_XOR_WriteProcessMemory_ad9e {
  strings:
    $key_ad9e = { fa ec [2] c8 ce [2] ce fb [2] e0 fb [2] df e7 }

  condition:
    any of them
}