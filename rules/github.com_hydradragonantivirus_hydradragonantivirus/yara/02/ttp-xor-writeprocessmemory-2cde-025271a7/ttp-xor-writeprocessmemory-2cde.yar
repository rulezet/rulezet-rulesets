rule TTP_XOR_WriteProcessMemory_2cde {
  strings:
    $key_2cde = { 7b ac [2] 49 8e [2] 4f bb [2] 61 bb [2] 5e a7 }

  condition:
    any of them
}