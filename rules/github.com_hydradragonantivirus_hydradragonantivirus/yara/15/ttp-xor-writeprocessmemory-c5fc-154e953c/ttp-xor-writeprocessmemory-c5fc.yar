rule TTP_XOR_WriteProcessMemory_c5fc {
  strings:
    $key_c5fc = { 92 8e [2] a0 ac [2] a6 99 [2] 88 99 [2] b7 85 }

  condition:
    any of them
}