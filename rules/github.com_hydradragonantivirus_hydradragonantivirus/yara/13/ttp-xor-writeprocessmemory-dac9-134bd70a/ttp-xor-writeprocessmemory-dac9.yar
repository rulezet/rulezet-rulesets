rule TTP_XOR_WriteProcessMemory_dac9 {
  strings:
    $key_dac9 = { 8d bb [2] bf 99 [2] b9 ac [2] 97 ac [2] a8 b0 }

  condition:
    any of them
}