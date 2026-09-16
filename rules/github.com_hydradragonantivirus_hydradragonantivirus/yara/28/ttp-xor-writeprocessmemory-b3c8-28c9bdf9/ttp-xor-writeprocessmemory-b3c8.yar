rule TTP_XOR_WriteProcessMemory_b3c8 {
  strings:
    $key_b3c8 = { e4 ba [2] d6 98 [2] d0 ad [2] fe ad [2] c1 b1 }

  condition:
    any of them
}