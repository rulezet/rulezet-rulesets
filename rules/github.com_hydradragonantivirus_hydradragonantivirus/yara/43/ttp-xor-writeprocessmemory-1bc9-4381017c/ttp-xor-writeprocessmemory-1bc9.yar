rule TTP_XOR_WriteProcessMemory_1bc9 {
  strings:
    $key_1bc9 = { 4c bb [2] 7e 99 [2] 78 ac [2] 56 ac [2] 69 b0 }

  condition:
    any of them
}