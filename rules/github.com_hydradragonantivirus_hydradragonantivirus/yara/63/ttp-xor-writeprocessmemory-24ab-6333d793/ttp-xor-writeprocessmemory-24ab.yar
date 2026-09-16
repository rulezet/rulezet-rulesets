rule TTP_XOR_WriteProcessMemory_24ab {
  strings:
    $key_24ab = { 73 d9 [2] 41 fb [2] 47 ce [2] 69 ce [2] 56 d2 }

  condition:
    any of them
}