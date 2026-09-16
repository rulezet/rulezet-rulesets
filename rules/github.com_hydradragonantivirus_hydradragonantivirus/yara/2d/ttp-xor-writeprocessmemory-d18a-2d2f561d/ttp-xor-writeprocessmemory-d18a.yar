rule TTP_XOR_WriteProcessMemory_d18a {
  strings:
    $key_d18a = { 86 f8 [2] b4 da [2] b2 ef [2] 9c ef [2] a3 f3 }

  condition:
    any of them
}