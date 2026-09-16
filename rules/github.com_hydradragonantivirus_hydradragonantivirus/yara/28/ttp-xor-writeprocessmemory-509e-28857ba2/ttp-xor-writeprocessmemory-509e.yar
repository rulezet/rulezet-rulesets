rule TTP_XOR_WriteProcessMemory_509e {
  strings:
    $key_509e = { 07 ec [2] 35 ce [2] 33 fb [2] 1d fb [2] 22 e7 }

  condition:
    any of them
}