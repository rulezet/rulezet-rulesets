rule TTP_XOR_WriteProcessMemory_4ac9 {
  strings:
    $key_4ac9 = { 1d bb [2] 2f 99 [2] 29 ac [2] 07 ac [2] 38 b0 }

  condition:
    any of them
}