rule TTP_XOR_WriteProcessMemory_cade {
  strings:
    $key_cade = { 9d ac [2] af 8e [2] a9 bb [2] 87 bb [2] b8 a7 }

  condition:
    any of them
}