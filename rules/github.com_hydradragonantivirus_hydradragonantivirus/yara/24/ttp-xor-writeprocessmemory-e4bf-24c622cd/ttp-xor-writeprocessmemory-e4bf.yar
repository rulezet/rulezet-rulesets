rule TTP_XOR_WriteProcessMemory_e4bf {
  strings:
    $key_e4bf = { b3 cd [2] 81 ef [2] 87 da [2] a9 da [2] 96 c6 }

  condition:
    any of them
}