rule TTP_XOR_WriteProcessMemory_6fde {
  strings:
    $key_6fde = { 38 ac [2] 0a 8e [2] 0c bb [2] 22 bb [2] 1d a7 }

  condition:
    any of them
}