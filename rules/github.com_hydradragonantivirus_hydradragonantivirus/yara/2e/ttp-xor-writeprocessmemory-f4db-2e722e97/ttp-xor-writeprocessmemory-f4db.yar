rule TTP_XOR_WriteProcessMemory_f4db {
  strings:
    $key_f4db = { a3 a9 [2] 91 8b [2] 97 be [2] b9 be [2] 86 a2 }

  condition:
    any of them
}