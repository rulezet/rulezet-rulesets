rule TTP_XOR_WriteProcessMemory_c4fc {
  strings:
    $key_c4fc = { 93 8e [2] a1 ac [2] a7 99 [2] 89 99 [2] b6 85 }

  condition:
    any of them
}