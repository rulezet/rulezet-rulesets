rule TTP_XOR_WriteProcessMemory_ddab {
  strings:
    $key_ddab = { 8a d9 [2] b8 fb [2] be ce [2] 90 ce [2] af d2 }

  condition:
    any of them
}