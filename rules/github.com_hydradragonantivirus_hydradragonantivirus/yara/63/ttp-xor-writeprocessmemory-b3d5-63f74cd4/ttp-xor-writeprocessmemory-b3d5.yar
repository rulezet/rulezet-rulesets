rule TTP_XOR_WriteProcessMemory_b3d5 {
  strings:
    $key_b3d5 = { e4 a7 [2] d6 85 [2] d0 b0 [2] fe b0 [2] c1 ac }

  condition:
    any of them
}