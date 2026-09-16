rule TTP_XOR_WriteProcessMemory_ecde {
  strings:
    $key_ecde = { bb ac [2] 89 8e [2] 8f bb [2] a1 bb [2] 9e a7 }

  condition:
    any of them
}