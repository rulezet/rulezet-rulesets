rule TTP_XOR_WriteProcessMemory_bade {
  strings:
    $key_bade = { ed ac [2] df 8e [2] d9 bb [2] f7 bb [2] c8 a7 }

  condition:
    any of them
}