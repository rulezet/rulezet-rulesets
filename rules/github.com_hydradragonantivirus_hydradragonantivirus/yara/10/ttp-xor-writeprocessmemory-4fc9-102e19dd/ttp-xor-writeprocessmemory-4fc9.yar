rule TTP_XOR_WriteProcessMemory_4fc9 {
  strings:
    $key_4fc9 = { 18 bb [2] 2a 99 [2] 2c ac [2] 02 ac [2] 3d b0 }

  condition:
    any of them
}