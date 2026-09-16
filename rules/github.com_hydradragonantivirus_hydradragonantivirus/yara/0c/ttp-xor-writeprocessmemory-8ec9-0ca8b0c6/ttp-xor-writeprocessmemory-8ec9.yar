rule TTP_XOR_WriteProcessMemory_8ec9 {
  strings:
    $key_8ec9 = { d9 bb [2] eb 99 [2] ed ac [2] c3 ac [2] fc b0 }

  condition:
    any of them
}