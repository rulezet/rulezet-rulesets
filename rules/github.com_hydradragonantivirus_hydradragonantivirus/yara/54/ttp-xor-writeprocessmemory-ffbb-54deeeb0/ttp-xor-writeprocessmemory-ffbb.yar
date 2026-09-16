rule TTP_XOR_WriteProcessMemory_ffbb {
  strings:
    $key_ffbb = { a8 c9 [2] 9a eb [2] 9c de [2] b2 de [2] 8d c2 }

  condition:
    any of them
}