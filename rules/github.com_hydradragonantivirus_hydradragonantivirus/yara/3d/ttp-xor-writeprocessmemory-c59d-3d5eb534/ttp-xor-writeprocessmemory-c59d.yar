rule TTP_XOR_WriteProcessMemory_c59d {
  strings:
    $key_c59d = { 92 ef [2] a0 cd [2] a6 f8 [2] 88 f8 [2] b7 e4 }

  condition:
    any of them
}