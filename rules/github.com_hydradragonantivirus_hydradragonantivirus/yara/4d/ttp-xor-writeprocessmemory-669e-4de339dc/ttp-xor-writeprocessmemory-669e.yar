rule TTP_XOR_WriteProcessMemory_669e {
  strings:
    $key_669e = { 31 ec [2] 03 ce [2] 05 fb [2] 2b fb [2] 14 e7 }

  condition:
    any of them
}