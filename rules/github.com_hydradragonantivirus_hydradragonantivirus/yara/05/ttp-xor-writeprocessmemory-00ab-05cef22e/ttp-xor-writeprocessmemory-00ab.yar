rule TTP_XOR_WriteProcessMemory_00ab {
  strings:
    $key_00ab = { 57 d9 [2] 65 fb [2] 63 ce [2] 4d ce [2] 72 d2 }

  condition:
    any of them
}