rule TTP_XOR_WriteProcessMemory_c2fc {
  strings:
    $key_c2fc = { 95 8e [2] a7 ac [2] a1 99 [2] 8f 99 [2] b0 85 }

  condition:
    any of them
}