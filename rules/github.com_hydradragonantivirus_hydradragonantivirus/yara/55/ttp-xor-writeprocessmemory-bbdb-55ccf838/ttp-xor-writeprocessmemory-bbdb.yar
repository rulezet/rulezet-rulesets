rule TTP_XOR_WriteProcessMemory_bbdb {
  strings:
    $key_bbdb = { ec a9 [2] de 8b [2] d8 be [2] f6 be [2] c9 a2 }

  condition:
    any of them
}