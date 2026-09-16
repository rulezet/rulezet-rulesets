rule TTP_XOR_WriteProcessMemory_c7bd {
  strings:
    $key_c7bd = { 90 cf [2] a2 ed [2] a4 d8 [2] 8a d8 [2] b5 c4 }

  condition:
    any of them
}