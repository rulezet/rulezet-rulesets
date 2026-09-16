rule TTP_XOR_WriteProcessMemory_a4bf {
  strings:
    $key_a4bf = { f3 cd [2] c1 ef [2] c7 da [2] e9 da [2] d6 c6 }

  condition:
    any of them
}