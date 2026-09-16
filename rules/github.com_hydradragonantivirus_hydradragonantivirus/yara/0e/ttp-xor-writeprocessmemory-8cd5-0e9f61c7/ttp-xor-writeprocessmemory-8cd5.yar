rule TTP_XOR_WriteProcessMemory_8cd5 {
  strings:
    $key_8cd5 = { db a7 [2] e9 85 [2] ef b0 [2] c1 b0 [2] fe ac }

  condition:
    any of them
}