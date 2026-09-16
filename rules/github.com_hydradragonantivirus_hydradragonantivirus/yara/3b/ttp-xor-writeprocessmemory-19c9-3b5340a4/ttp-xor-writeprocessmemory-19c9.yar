rule TTP_XOR_WriteProcessMemory_19c9 {
  strings:
    $key_19c9 = { 4e bb [2] 7c 99 [2] 7a ac [2] 54 ac [2] 6b b0 }

  condition:
    any of them
}