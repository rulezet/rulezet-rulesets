rule TTP_XOR_WriteProcessMemory_7bde {
  strings:
    $key_7bde = { 2c ac [2] 1e 8e [2] 18 bb [2] 36 bb [2] 09 a7 }

  condition:
    any of them
}