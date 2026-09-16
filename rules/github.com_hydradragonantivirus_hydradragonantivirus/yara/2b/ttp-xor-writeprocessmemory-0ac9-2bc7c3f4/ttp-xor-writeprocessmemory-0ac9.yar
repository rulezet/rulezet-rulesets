rule TTP_XOR_WriteProcessMemory_0ac9 {
  strings:
    $key_0ac9 = { 5d bb [2] 6f 99 [2] 69 ac [2] 47 ac [2] 78 b0 }

  condition:
    any of them
}