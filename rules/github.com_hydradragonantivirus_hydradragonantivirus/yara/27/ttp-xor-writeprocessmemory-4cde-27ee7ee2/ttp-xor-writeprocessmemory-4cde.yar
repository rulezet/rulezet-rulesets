rule TTP_XOR_WriteProcessMemory_4cde {
  strings:
    $key_4cde = { 1b ac [2] 29 8e [2] 2f bb [2] 01 bb [2] 3e a7 }

  condition:
    any of them
}