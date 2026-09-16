rule TTP_XOR_WriteProcessMemory_62ab {
  strings:
    $key_62ab = { 35 d9 [2] 07 fb [2] 01 ce [2] 2f ce [2] 10 d2 }

  condition:
    any of them
}