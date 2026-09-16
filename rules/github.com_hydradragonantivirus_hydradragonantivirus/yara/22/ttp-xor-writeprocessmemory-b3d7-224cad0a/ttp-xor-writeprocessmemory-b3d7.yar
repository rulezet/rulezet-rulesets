rule TTP_XOR_WriteProcessMemory_b3d7 {
  strings:
    $key_b3d7 = { e4 a5 [2] d6 87 [2] d0 b2 [2] fe b2 [2] c1 ae }

  condition:
    any of them
}