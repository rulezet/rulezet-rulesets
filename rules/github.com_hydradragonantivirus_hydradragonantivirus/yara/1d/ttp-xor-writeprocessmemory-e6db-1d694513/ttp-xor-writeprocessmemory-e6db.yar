rule TTP_XOR_WriteProcessMemory_e6db {
  strings:
    $key_e6db = { b1 a9 [2] 83 8b [2] 85 be [2] ab be [2] 94 a2 }

  condition:
    any of them
}