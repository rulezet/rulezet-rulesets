rule TTP_XOR_WriteProcessMemory_a48a {
  strings:
    $key_a48a = { f3 f8 [2] c1 da [2] c7 ef [2] e9 ef [2] d6 f3 }

  condition:
    any of them
}