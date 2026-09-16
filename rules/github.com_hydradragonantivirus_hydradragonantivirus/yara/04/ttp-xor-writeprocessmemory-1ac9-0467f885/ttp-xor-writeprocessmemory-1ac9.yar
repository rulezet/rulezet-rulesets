rule TTP_XOR_WriteProcessMemory_1ac9 {
  strings:
    $key_1ac9 = { 4d bb [2] 7f 99 [2] 79 ac [2] 57 ac [2] 68 b0 }

  condition:
    any of them
}