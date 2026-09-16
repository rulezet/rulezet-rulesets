rule TTP_XOR_WriteProcessMemory_4fde {
  strings:
    $key_4fde = { 18 ac [2] 2a 8e [2] 2c bb [2] 02 bb [2] 3d a7 }

  condition:
    any of them
}