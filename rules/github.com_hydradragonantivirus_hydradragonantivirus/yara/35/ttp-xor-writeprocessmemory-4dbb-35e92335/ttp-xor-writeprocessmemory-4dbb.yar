rule TTP_XOR_WriteProcessMemory_4dbb {
  strings:
    $key_4dbb = { 1a c9 [2] 28 eb [2] 2e de [2] 00 de [2] 3f c2 }

  condition:
    any of them
}