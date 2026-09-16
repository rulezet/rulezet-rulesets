rule TTP_XOR_WriteProcessMemory_5ac9 {
  strings:
    $key_5ac9 = { 0d bb [2] 3f 99 [2] 39 ac [2] 17 ac [2] 28 b0 }

  condition:
    any of them
}