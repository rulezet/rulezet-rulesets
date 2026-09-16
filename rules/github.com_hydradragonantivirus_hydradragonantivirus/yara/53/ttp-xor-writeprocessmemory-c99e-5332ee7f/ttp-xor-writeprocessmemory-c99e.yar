rule TTP_XOR_WriteProcessMemory_c99e {
  strings:
    $key_c99e = { 9e ec [2] ac ce [2] aa fb [2] 84 fb [2] bb e7 }

  condition:
    any of them
}