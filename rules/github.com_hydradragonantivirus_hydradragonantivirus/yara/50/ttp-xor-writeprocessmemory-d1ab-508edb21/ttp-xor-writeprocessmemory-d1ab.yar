rule TTP_XOR_WriteProcessMemory_d1ab {
  strings:
    $key_d1ab = { 86 d9 [2] b4 fb [2] b2 ce [2] 9c ce [2] a3 d2 }

  condition:
    any of them
}