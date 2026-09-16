rule TTP_XOR_WriteProcessMemory_99c9 {
  strings:
    $key_99c9 = { ce bb [2] fc 99 [2] fa ac [2] d4 ac [2] eb b0 }

  condition:
    any of them
}