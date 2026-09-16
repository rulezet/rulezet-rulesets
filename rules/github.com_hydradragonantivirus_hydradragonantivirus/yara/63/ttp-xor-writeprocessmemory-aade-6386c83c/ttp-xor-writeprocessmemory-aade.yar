rule TTP_XOR_WriteProcessMemory_aade {
  strings:
    $key_aade = { fd ac [2] cf 8e [2] c9 bb [2] e7 bb [2] d8 a7 }

  condition:
    any of them
}