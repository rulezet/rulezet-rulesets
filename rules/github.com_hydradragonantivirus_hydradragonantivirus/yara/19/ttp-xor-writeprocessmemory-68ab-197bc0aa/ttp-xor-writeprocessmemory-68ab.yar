rule TTP_XOR_WriteProcessMemory_68ab {
  strings:
    $key_68ab = { 3f d9 [2] 0d fb [2] 0b ce [2] 25 ce [2] 1a d2 }

  condition:
    any of them
}