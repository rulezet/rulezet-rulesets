rule TTP_XOR_WriteProcessMemory_b3bf {
  strings:
    $key_b3bf = { e4 cd [2] d6 ef [2] d0 da [2] fe da [2] c1 c6 }

  condition:
    any of them
}