rule TTP_XOR_WriteProcessMemory_c33d {
  strings:
    $key_c33d = { 94 4f [2] a6 6d [2] a0 58 [2] 8e 58 [2] b1 44 }

  condition:
    any of them
}