rule TTP_XOR_WriteProcessMemory_fcab {
  strings:
    $key_fcab = { ab d9 [2] 99 fb [2] 9f ce [2] b1 ce [2] 8e d2 }

  condition:
    any of them
}