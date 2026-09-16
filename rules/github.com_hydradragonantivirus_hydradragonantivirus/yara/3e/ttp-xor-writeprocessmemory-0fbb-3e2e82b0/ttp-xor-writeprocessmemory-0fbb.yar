rule TTP_XOR_WriteProcessMemory_0fbb {
  strings:
    $key_0fbb = { 58 c9 [2] 6a eb [2] 6c de [2] 42 de [2] 7d c2 }

  condition:
    any of them
}