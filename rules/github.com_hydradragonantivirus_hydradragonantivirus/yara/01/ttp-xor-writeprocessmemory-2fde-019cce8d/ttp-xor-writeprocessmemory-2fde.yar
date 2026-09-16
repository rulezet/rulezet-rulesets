rule TTP_XOR_WriteProcessMemory_2fde {
  strings:
    $key_2fde = { 78 ac [2] 4a 8e [2] 4c bb [2] 62 bb [2] 5d a7 }

  condition:
    any of them
}