rule TTP_XOR_WriteProcessMemory_5dbb {
  strings:
    $key_5dbb = { 0a c9 [2] 38 eb [2] 3e de [2] 10 de [2] 2f c2 }

  condition:
    any of them
}