rule TTP_XOR_WriteProcessMemory_7cc9 {
  strings:
    $key_7cc9 = { 2b bb [2] 19 99 [2] 1f ac [2] 31 ac [2] 0e b0 }

  condition:
    any of them
}