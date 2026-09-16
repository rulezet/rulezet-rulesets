rule TTP_XOR_WriteProcessMemory_d5fc {
  strings:
    $key_d5fc = { 82 8e [2] b0 ac [2] b6 99 [2] 98 99 [2] a7 85 }

  condition:
    any of them
}