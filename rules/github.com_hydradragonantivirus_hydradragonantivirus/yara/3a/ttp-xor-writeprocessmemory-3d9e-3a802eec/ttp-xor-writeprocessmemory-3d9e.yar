rule TTP_XOR_WriteProcessMemory_3d9e {
  strings:
    $key_3d9e = { 6a ec [2] 58 ce [2] 5e fb [2] 70 fb [2] 4f e7 }

  condition:
    any of them
}