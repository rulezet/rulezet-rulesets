rule TTP_XOR_WriteProcessMemory_14ab {
  strings:
    $key_14ab = { 43 d9 [2] 71 fb [2] 77 ce [2] 59 ce [2] 66 d2 }

  condition:
    any of them
}