rule TTP_XOR_WriteProcessMemory_e1c9 {
  strings:
    $key_e1c9 = { b6 bb [2] 84 99 [2] 82 ac [2] ac ac [2] 93 b0 }

  condition:
    any of them
}