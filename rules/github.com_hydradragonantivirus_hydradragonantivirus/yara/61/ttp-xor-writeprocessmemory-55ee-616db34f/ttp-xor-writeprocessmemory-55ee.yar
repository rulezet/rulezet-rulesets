rule TTP_XOR_WriteProcessMemory_55ee {
  strings:
    $key_55ee = { 02 9c [2] 30 be [2] 36 8b [2] 18 8b [2] 27 97 }

  condition:
    any of them
}