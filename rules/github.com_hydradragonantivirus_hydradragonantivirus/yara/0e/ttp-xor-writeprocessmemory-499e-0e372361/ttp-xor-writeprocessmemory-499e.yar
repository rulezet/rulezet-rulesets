rule TTP_XOR_WriteProcessMemory_499e {
  strings:
    $key_499e = { 1e ec [2] 2c ce [2] 2a fb [2] 04 fb [2] 3b e7 }

  condition:
    any of them
}