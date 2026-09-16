rule TTP_XOR_WriteProcessMemory_91db {
  strings:
    $key_91db = { c6 a9 [2] f4 8b [2] f2 be [2] dc be [2] e3 a2 }

  condition:
    any of them
}