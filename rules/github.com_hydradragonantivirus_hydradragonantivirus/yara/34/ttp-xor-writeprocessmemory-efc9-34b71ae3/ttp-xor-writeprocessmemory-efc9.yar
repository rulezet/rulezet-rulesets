rule TTP_XOR_WriteProcessMemory_efc9 {
  strings:
    $key_efc9 = { b8 bb [2] 8a 99 [2] 8c ac [2] a2 ac [2] 9d b0 }

  condition:
    any of them
}