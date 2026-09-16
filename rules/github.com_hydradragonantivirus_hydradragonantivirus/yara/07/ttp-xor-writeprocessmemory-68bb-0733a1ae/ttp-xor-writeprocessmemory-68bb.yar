rule TTP_XOR_WriteProcessMemory_68bb {
  strings:
    $key_68bb = { 3f c9 [2] 0d eb [2] 0b de [2] 25 de [2] 1a c2 }

  condition:
    any of them
}