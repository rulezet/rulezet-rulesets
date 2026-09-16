rule TTP_XOR_WriteProcessMemory_ccab {
  strings:
    $key_ccab = { 9b d9 [2] a9 fb [2] af ce [2] 81 ce [2] be d2 }

  condition:
    any of them
}