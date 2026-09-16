rule TTP_XOR_WriteProcessMemory_c3d7 {
  strings:
    $key_c3d7 = { 94 a5 [2] a6 87 [2] a0 b2 [2] 8e b2 [2] b1 ae }

  condition:
    any of them
}