rule TTP_XOR_WriteProcessMemory_609e {
  strings:
    $key_609e = { 37 ec [2] 05 ce [2] 03 fb [2] 2d fb [2] 12 e7 }

  condition:
    any of them
}