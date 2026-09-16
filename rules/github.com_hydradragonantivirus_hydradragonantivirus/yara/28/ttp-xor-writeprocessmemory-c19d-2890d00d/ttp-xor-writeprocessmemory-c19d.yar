rule TTP_XOR_WriteProcessMemory_c19d {
  strings:
    $key_c19d = { 96 ef [2] a4 cd [2] a2 f8 [2] 8c f8 [2] b3 e4 }

  condition:
    any of them
}