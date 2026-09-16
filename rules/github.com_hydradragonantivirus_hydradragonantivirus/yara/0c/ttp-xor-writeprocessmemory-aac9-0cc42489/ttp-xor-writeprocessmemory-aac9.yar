rule TTP_XOR_WriteProcessMemory_aac9 {
  strings:
    $key_aac9 = { fd bb [2] cf 99 [2] c9 ac [2] e7 ac [2] d8 b0 }

  condition:
    any of them
}