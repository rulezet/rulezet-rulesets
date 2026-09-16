rule TTP_XOR_WriteProcessMemory_c48a {
  strings:
    $key_c48a = { 93 f8 [2] a1 da [2] a7 ef [2] 89 ef [2] b6 f3 }

  condition:
    any of them
}