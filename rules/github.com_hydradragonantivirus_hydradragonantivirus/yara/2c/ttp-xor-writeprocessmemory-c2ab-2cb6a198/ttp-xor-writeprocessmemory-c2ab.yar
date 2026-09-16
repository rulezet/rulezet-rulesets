rule TTP_XOR_WriteProcessMemory_c2ab {
  strings:
    $key_c2ab = { 95 d9 [2] a7 fb [2] a1 ce [2] 8f ce [2] b0 d2 }

  condition:
    any of them
}