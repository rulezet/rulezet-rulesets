rule TTP_XOR_WriteProcessMemory_6cde {
  strings:
    $key_6cde = { 3b ac [2] 09 8e [2] 0f bb [2] 21 bb [2] 1e a7 }

  condition:
    any of them
}