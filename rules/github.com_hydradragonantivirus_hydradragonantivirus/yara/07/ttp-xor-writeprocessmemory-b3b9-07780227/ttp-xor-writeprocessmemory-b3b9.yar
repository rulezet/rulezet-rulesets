rule TTP_XOR_WriteProcessMemory_b3b9 {
  strings:
    $key_b3b9 = { e4 cb [2] d6 e9 [2] d0 dc [2] fe dc [2] c1 c0 }

  condition:
    any of them
}