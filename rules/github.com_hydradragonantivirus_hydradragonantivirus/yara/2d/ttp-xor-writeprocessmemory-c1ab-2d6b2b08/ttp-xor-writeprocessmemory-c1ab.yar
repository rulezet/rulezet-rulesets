rule TTP_XOR_WriteProcessMemory_c1ab {
  strings:
    $key_c1ab = { 96 d9 [2] a4 fb [2] a2 ce [2] 8c ce [2] b3 d2 }

  condition:
    any of them
}