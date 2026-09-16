rule TTP_XOR_WriteProcessMemory_8fdb {
  strings:
    $key_8fdb = { d8 a9 [2] ea 8b [2] ec be [2] c2 be [2] fd a2 }

  condition:
    any of them
}