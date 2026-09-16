rule TTP_XOR_WriteProcessMemory_c3fc {
  strings:
    $key_c3fc = { 94 8e [2] a6 ac [2] a0 99 [2] 8e 99 [2] b1 85 }

  condition:
    any of them
}