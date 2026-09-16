rule TTP_XOR_WriteProcessMemory_d2fc {
  strings:
    $key_d2fc = { 85 8e [2] b7 ac [2] b1 99 [2] 9f 99 [2] a0 85 }

  condition:
    any of them
}