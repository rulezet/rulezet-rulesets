rule TTP_XOR_WriteProcessMemory_3cc9 {
  strings:
    $key_3cc9 = { 6b bb [2] 59 99 [2] 5f ac [2] 71 ac [2] 4e b0 }

  condition:
    any of them
}