rule TTP_XOR_WriteProcessMemory_9fc9 {
  strings:
    $key_9fc9 = { c8 bb [2] fa 99 [2] fc ac [2] d2 ac [2] ed b0 }

  condition:
    any of them
}