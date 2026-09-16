rule TTP_XOR_WriteProcessMemory_cb9e {
  strings:
    $key_cb9e = { 9c ec [2] ae ce [2] a8 fb [2] 86 fb [2] b9 e7 }

  condition:
    any of them
}