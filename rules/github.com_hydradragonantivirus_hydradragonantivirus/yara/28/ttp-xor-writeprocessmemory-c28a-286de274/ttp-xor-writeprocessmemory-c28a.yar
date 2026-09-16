rule TTP_XOR_WriteProcessMemory_c28a {
  strings:
    $key_c28a = { 95 f8 [2] a7 da [2] a1 ef [2] 8f ef [2] b0 f3 }

  condition:
    any of them
}