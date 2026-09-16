rule TTP_XOR_WriteProcessMemory_e3ab {
  strings:
    $key_e3ab = { b4 d9 [2] 86 fb [2] 80 ce [2] ae ce [2] 91 d2 }

  condition:
    any of them
}