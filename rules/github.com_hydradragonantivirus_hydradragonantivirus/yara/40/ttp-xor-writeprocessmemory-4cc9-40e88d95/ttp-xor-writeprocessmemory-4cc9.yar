rule TTP_XOR_WriteProcessMemory_4cc9 {
  strings:
    $key_4cc9 = { 1b bb [2] 29 99 [2] 2f ac [2] 01 ac [2] 3e b0 }

  condition:
    any of them
}