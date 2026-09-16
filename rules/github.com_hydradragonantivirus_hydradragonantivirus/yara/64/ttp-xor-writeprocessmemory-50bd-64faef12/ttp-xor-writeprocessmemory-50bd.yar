rule TTP_XOR_WriteProcessMemory_50bd {
  strings:
    $key_50bd = { 07 cf [2] 35 ed [2] 33 d8 [2] 1d d8 [2] 22 c4 }

  condition:
    any of them
}