rule TTP_XOR_WriteProcessMemory_c1fc {
  strings:
    $key_c1fc = { 96 8e [2] a4 ac [2] a2 99 [2] 8c 99 [2] b3 85 }

  condition:
    any of them
}