rule TTP_XOR_WriteProcessMemory_c5ab {
  strings:
    $key_c5ab = { 92 d9 [2] a0 fb [2] a6 ce [2] 88 ce [2] b7 d2 }

  condition:
    any of them
}