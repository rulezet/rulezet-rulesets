rule TTP_XOR_WriteProcessMemory_0aab {
  strings:
    $key_0aab = { 5d d9 [2] 6f fb [2] 69 ce [2] 47 ce [2] 78 d2 }

  condition:
    any of them
}