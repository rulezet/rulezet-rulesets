rule TTP_XOR_WriteProcessMemory_bbbb {
  strings:
    $key_bbbb = { ec c9 [2] de eb [2] d8 de [2] f6 de [2] c9 c2 }

  condition:
    any of them
}