rule TTP_XOR_WriteProcessMemory_e6ab {
  strings:
    $key_e6ab = { b1 d9 [2] 83 fb [2] 85 ce [2] ab ce [2] 94 d2 }

  condition:
    any of them
}