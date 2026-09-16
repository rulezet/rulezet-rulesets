rule TTP_XOR_WriteProcessMemory_cdbc {
  strings:
    $key_cdbc = { 9a ce [2] a8 ec [2] ae d9 [2] 80 d9 [2] bf c5 }

  condition:
    any of them
}