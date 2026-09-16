rule TTP_XOR_WriteProcessMemory_2fbb {
  strings:
    $key_2fbb = { 78 c9 [2] 4a eb [2] 4c de [2] 62 de [2] 5d c2 }

  condition:
    any of them
}