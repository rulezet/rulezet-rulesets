rule TTP_XOR_WriteProcessMemory_d1bd {
  strings:
    $key_d1bd = { 86 cf [2] b4 ed [2] b2 d8 [2] 9c d8 [2] a3 c4 }

  condition:
    any of them
}