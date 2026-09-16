rule TTP_XOR_WriteProcessMemory_b7bf {
  strings:
    $key_b7bf = { e0 cd [2] d2 ef [2] d4 da [2] fa da [2] c5 c6 }

  condition:
    any of them
}