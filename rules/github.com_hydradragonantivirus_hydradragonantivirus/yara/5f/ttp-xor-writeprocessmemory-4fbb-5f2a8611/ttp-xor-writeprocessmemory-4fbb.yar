rule TTP_XOR_WriteProcessMemory_4fbb {
  strings:
    $key_4fbb = { 18 c9 [2] 2a eb [2] 2c de [2] 02 de [2] 3d c2 }

  condition:
    any of them
}