rule TTP_XOR_WriteProcessMemory_49c9 {
  strings:
    $key_49c9 = { 1e bb [2] 2c 99 [2] 2a ac [2] 04 ac [2] 3b b0 }

  condition:
    any of them
}