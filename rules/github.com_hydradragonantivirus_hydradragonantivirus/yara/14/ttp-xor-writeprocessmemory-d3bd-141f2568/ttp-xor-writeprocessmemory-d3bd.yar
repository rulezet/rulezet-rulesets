rule TTP_XOR_WriteProcessMemory_d3bd {
  strings:
    $key_d3bd = { 84 cf [2] b6 ed [2] b0 d8 [2] 9e d8 [2] a1 c4 }

  condition:
    any of them
}