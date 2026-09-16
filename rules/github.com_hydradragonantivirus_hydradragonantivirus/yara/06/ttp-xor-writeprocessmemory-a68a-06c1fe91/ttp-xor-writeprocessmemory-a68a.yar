rule TTP_XOR_WriteProcessMemory_a68a {
  strings:
    $key_a68a = { f1 f8 [2] c3 da [2] c5 ef [2] eb ef [2] d4 f3 }

  condition:
    any of them
}