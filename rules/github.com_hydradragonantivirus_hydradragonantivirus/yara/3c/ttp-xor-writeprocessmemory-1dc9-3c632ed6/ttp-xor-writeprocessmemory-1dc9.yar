rule TTP_XOR_WriteProcessMemory_1dc9 {
  strings:
    $key_1dc9 = { 4a bb [2] 78 99 [2] 7e ac [2] 50 ac [2] 6f b0 }

  condition:
    any of them
}