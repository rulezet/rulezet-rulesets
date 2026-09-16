rule TTP_XOR_WriteProcessMemory_d99e {
  strings:
    $key_d99e = { 8e ec [2] bc ce [2] ba fb [2] 94 fb [2] ab e7 }

  condition:
    any of them
}