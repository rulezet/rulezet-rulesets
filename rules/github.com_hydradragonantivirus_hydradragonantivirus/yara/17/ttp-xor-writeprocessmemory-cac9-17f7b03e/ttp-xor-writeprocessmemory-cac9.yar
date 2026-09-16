rule TTP_XOR_WriteProcessMemory_cac9 {
  strings:
    $key_cac9 = { 9d bb [2] af 99 [2] a9 ac [2] 87 ac [2] b8 b0 }

  condition:
    any of them
}