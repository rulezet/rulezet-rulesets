rule TTP_XOR_WriteProcessMemory_c09e {
  strings:
    $key_c09e = { 97 ec [2] a5 ce [2] a3 fb [2] 8d fb [2] b2 e7 }

  condition:
    any of them
}