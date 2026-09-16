rule TTP_XOR_WriteProcessMemory_b391 {
  strings:
    $key_b391 = { e4 e3 [2] d6 c1 [2] d0 f4 [2] fe f4 [2] c1 e8 }

  condition:
    any of them
}