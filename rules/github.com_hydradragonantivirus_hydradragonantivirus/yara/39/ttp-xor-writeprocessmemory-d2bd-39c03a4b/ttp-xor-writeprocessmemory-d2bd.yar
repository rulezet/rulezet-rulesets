rule TTP_XOR_WriteProcessMemory_d2bd {
  strings:
    $key_d2bd = { 85 cf [2] b7 ed [2] b1 d8 [2] 9f d8 [2] a0 c4 }

  condition:
    any of them
}