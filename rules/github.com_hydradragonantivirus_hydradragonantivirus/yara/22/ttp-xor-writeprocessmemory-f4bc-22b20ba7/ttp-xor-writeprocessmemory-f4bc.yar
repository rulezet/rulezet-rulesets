rule TTP_XOR_WriteProcessMemory_f4bc {
  strings:
    $key_f4bc = { a3 ce [2] 91 ec [2] 97 d9 [2] b9 d9 [2] 86 c5 }

  condition:
    any of them
}