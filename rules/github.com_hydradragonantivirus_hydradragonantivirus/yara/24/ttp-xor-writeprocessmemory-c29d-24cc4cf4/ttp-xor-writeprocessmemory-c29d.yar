rule TTP_XOR_WriteProcessMemory_c29d {
  strings:
    $key_c29d = { 95 ef [2] a7 cd [2] a1 f8 [2] 8f f8 [2] b0 e4 }

  condition:
    any of them
}