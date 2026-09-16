rule TTP_XOR_WriteProcessMemory_c1bd {
  strings:
    $key_c1bd = { 96 cf [2] a4 ed [2] a2 d8 [2] 8c d8 [2] b3 c4 }

  condition:
    any of them
}