rule TTP_XOR_WriteProcessMemory_3aab {
  strings:
    $key_3aab = { 6d d9 [2] 5f fb [2] 59 ce [2] 77 ce [2] 48 d2 }

  condition:
    any of them
}