rule TTP_XOR_WriteProcessMemory_e2ab {
  strings:
    $key_e2ab = { b5 d9 [2] 87 fb [2] 81 ce [2] af ce [2] 90 d2 }

  condition:
    any of them
}