rule TTP_XOR_WriteProcessMemory_a2bf {
  strings:
    $key_a2bf = { f5 cd [2] c7 ef [2] c1 da [2] ef da [2] d0 c6 }

  condition:
    any of them
}