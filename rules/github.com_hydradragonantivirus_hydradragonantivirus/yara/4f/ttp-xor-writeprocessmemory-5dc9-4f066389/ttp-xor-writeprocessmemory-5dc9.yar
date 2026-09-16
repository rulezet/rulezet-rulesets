rule TTP_XOR_WriteProcessMemory_5dc9 {
  strings:
    $key_5dc9 = { 0a bb [2] 38 99 [2] 3e ac [2] 10 ac [2] 2f b0 }

  condition:
    any of them
}