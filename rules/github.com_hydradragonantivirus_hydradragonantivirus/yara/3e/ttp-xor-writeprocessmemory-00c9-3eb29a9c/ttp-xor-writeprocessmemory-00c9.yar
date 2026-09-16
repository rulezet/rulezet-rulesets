rule TTP_XOR_WriteProcessMemory_00c9 {
  strings:
    $key_00c9 = { 57 bb [2] 65 99 [2] 63 ac [2] 4d ac [2] 72 b0 }

  condition:
    any of them
}