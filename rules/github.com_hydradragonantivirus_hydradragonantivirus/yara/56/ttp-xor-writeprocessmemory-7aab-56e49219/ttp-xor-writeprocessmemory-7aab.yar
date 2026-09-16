rule TTP_XOR_WriteProcessMemory_7aab {
  strings:
    $key_7aab = { 2d d9 [2] 1f fb [2] 19 ce [2] 37 ce [2] 08 d2 }

  condition:
    any of them
}