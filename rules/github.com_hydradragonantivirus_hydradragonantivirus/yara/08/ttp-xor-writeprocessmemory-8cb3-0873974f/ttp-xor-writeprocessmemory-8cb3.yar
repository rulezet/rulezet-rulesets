rule TTP_XOR_WriteProcessMemory_8cb3 {
  strings:
    $key_8cb3 = { db c1 [2] e9 e3 [2] ef d6 [2] c1 d6 [2] fe ca }

  condition:
    any of them
}