rule TTP_XOR_WriteProcessMemory_5fcc {
  strings:
    $key_5fcc = { 08 be [2] 3a 9c [2] 3c a9 [2] 12 a9 [2] 2d b5 }

  condition:
    any of them
}