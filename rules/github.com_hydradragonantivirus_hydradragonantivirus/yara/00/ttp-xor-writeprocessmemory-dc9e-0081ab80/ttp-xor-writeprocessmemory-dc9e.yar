rule TTP_XOR_WriteProcessMemory_dc9e {
  strings:
    $key_dc9e = { 8b ec [2] b9 ce [2] bf fb [2] 91 fb [2] ae e7 }

  condition:
    any of them
}