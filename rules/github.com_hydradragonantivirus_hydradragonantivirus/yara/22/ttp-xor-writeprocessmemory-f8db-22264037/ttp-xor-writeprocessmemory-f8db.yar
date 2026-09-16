rule TTP_XOR_WriteProcessMemory_f8db {
  strings:
    $key_f8db = { af a9 [2] 9d 8b [2] 9b be [2] b5 be [2] 8a a2 }

  condition:
    any of them
}