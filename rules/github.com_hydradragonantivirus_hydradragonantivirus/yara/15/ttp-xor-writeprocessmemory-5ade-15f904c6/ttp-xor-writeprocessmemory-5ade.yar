rule TTP_XOR_WriteProcessMemory_5ade {
  strings:
    $key_5ade = { 0d ac [2] 3f 8e [2] 39 bb [2] 17 bb [2] 28 a7 }

  condition:
    any of them
}