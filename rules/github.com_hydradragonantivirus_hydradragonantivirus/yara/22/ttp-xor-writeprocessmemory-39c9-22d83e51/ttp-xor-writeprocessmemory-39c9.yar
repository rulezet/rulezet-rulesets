rule TTP_XOR_WriteProcessMemory_39c9 {
  strings:
    $key_39c9 = { 6e bb [2] 5c 99 [2] 5a ac [2] 74 ac [2] 4b b0 }

  condition:
    any of them
}