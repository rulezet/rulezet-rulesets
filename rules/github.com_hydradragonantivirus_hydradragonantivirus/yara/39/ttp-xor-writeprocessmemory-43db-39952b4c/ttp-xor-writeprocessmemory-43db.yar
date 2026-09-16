rule TTP_XOR_WriteProcessMemory_43db {
  strings:
    $key_43db = { 14 a9 [2] 26 8b [2] 20 be [2] 0e be [2] 31 a2 }

  condition:
    any of them
}