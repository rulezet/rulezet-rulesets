rule TTP_XOR_WriteProcessMemory_23bd {
  strings:
    $key_23bd = { 74 cf [2] 46 ed [2] 40 d8 [2] 6e d8 [2] 51 c4 }

  condition:
    any of them
}