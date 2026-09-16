rule TTP_XOR_WriteProcessMemory_c18a {
  strings:
    $key_c18a = { 96 f8 [2] a4 da [2] a2 ef [2] 8c ef [2] b3 f3 }

  condition:
    any of them
}