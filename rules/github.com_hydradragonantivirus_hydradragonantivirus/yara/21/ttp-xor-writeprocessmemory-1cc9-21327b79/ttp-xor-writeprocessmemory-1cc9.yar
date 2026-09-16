rule TTP_XOR_WriteProcessMemory_1cc9 {
  strings:
    $key_1cc9 = { 4b bb [2] 79 99 [2] 7f ac [2] 51 ac [2] 6e b0 }

  condition:
    any of them
}