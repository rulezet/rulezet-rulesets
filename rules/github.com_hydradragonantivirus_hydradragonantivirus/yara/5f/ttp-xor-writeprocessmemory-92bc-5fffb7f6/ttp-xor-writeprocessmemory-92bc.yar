rule TTP_XOR_WriteProcessMemory_92bc {
  strings:
    $key_92bc = { c5 ce [2] f7 ec [2] f1 d9 [2] df d9 [2] e0 c5 }

  condition:
    any of them
}