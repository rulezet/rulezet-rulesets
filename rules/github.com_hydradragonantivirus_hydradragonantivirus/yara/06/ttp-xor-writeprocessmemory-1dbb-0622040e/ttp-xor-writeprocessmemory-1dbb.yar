rule TTP_XOR_WriteProcessMemory_1dbb {
  strings:
    $key_1dbb = { 4a c9 [2] 78 eb [2] 7e de [2] 50 de [2] 6f c2 }

  condition:
    any of them
}