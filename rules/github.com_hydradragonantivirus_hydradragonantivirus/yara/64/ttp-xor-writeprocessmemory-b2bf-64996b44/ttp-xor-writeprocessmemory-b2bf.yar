rule TTP_XOR_WriteProcessMemory_b2bf {
  strings:
    $key_b2bf = { e5 cd [2] d7 ef [2] d1 da [2] ff da [2] c0 c6 }

  condition:
    any of them
}