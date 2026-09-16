rule TTP_XOR_WriteProcessMemory_06c9 {
  strings:
    $key_06c9 = { 51 bb [2] 63 99 [2] 65 ac [2] 4b ac [2] 74 b0 }

  condition:
    any of them
}