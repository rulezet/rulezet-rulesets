rule TTP_XOR_WriteProcessMemory_d7bd {
  strings:
    $key_d7bd = { 80 cf [2] b2 ed [2] b4 d8 [2] 9a d8 [2] a5 c4 }

  condition:
    any of them
}