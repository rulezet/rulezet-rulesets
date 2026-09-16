rule TTP_XOR_WriteProcessMemory_7dbb {
  strings:
    $key_7dbb = { 2a c9 [2] 18 eb [2] 1e de [2] 30 de [2] 0f c2 }

  condition:
    any of them
}