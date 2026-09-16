rule TTP_XOR_WriteProcessMemory_d5ab {
  strings:
    $key_d5ab = { 82 d9 [2] b0 fb [2] b6 ce [2] 98 ce [2] a7 d2 }

  condition:
    any of them
}