rule TTP_XOR_WriteProcessMemory_8cdc {
  strings:
    $key_8cdc = { db ae [2] e9 8c [2] ef b9 [2] c1 b9 [2] fe a5 }

  condition:
    any of them
}