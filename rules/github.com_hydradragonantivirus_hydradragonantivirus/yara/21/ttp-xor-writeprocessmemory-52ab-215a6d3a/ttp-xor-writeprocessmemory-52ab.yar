rule TTP_XOR_WriteProcessMemory_52ab {
  strings:
    $key_52ab = { 05 d9 [2] 37 fb [2] 31 ce [2] 1f ce [2] 20 d2 }

  condition:
    any of them
}