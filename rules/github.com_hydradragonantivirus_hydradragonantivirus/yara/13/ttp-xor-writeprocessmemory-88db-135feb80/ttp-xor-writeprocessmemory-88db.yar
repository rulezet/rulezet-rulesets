rule TTP_XOR_WriteProcessMemory_88db {
  strings:
    $key_88db = { df a9 [2] ed 8b [2] eb be [2] c5 be [2] fa a2 }

  condition:
    any of them
}