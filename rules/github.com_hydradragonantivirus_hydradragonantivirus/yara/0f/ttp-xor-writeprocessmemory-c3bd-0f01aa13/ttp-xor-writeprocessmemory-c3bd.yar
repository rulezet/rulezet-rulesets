rule TTP_XOR_WriteProcessMemory_c3bd {
  strings:
    $key_c3bd = { 94 cf [2] a6 ed [2] a0 d8 [2] 8e d8 [2] b1 c4 }

  condition:
    any of them
}