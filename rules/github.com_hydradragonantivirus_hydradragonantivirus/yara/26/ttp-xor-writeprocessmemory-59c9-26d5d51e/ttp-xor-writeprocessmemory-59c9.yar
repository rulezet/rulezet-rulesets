rule TTP_XOR_WriteProcessMemory_59c9 {
  strings:
    $key_59c9 = { 0e bb [2] 3c 99 [2] 3a ac [2] 14 ac [2] 2b b0 }

  condition:
    any of them
}