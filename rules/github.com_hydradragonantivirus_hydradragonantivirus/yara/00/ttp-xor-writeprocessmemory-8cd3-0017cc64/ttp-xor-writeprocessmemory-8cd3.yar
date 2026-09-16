rule TTP_XOR_WriteProcessMemory_8cd3 {
  strings:
    $key_8cd3 = { db a1 [2] e9 83 [2] ef b6 [2] c1 b6 [2] fe aa }

  condition:
    any of them
}