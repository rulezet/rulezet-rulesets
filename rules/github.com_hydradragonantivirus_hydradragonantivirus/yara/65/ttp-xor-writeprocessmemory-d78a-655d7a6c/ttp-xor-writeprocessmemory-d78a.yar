rule TTP_XOR_WriteProcessMemory_d78a {
  strings:
    $key_d78a = { 80 f8 [2] b2 da [2] b4 ef [2] 9a ef [2] a5 f3 }

  condition:
    any of them
}