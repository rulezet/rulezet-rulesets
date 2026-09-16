rule TTP_XOR_WriteProcessMemory_319e {
  strings:
    $key_319e = { 66 ec [2] 54 ce [2] 52 fb [2] 7c fb [2] 43 e7 }

  condition:
    any of them
}