rule TTP_XOR_WriteProcessMemory_8ccc {
  strings:
    $key_8ccc = { db be [2] e9 9c [2] ef a9 [2] c1 a9 [2] fe b5 }

  condition:
    any of them
}