rule TTP_XOR_WriteProcessMemory_5cde {
  strings:
    $key_5cde = { 0b ac [2] 39 8e [2] 3f bb [2] 11 bb [2] 2e a7 }

  condition:
    any of them
}