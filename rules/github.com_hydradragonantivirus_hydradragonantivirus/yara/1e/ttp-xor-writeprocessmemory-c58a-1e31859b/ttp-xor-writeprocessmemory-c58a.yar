rule TTP_XOR_WriteProcessMemory_c58a {
  strings:
    $key_c58a = { 92 f8 [2] a0 da [2] a6 ef [2] 88 ef [2] b7 f3 }

  condition:
    any of them
}