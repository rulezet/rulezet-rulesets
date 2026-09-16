rule TTP_XOR_WriteProcessMemory_c4bf {
  strings:
    $key_c4bf = { 93 cd [2] a1 ef [2] a7 da [2] 89 da [2] b6 c6 }

  condition:
    any of them
}