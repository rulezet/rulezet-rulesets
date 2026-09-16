rule TTP_XOR_WriteProcessMemory_d1fc {
  strings:
    $key_d1fc = { 86 8e [2] b4 ac [2] b2 99 [2] 9c 99 [2] a3 85 }

  condition:
    any of them
}