rule TTP_XOR_WriteProcessMemory_6bde {
  strings:
    $key_6bde = { 3c ac [2] 0e 8e [2] 08 bb [2] 26 bb [2] 19 a7 }

  condition:
    any of them
}