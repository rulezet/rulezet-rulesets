rule TTP_XOR_WriteProcessMemory_02ab {
  strings:
    $key_02ab = { 55 d9 [2] 67 fb [2] 61 ce [2] 4f ce [2] 70 d2 }

  condition:
    any of them
}