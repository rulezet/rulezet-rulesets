rule TTP_XOR_WriteProcessMemory_8c9b {
  strings:
    $key_8c9b = { db e9 [2] e9 cb [2] ef fe [2] c1 fe [2] fe e2 }

  condition:
    any of them
}