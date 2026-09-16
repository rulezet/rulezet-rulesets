rule TTP_XOR_WriteProcessMemory_c4bd {
  strings:
    $key_c4bd = { 93 cf [2] a1 ed [2] a7 d8 [2] 89 d8 [2] b6 c4 }

  condition:
    any of them
}