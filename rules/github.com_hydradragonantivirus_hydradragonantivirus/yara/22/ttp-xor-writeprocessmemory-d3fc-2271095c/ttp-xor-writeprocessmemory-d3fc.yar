rule TTP_XOR_WriteProcessMemory_d3fc {
  strings:
    $key_d3fc = { 84 8e [2] b6 ac [2] b0 99 [2] 9e 99 [2] a1 85 }

  condition:
    any of them
}