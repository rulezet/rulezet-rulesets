rule TTP_XOR_WriteProcessMemory_a7bd {
  strings:
    $key_a7bd = { f0 cf [2] c2 ed [2] c4 d8 [2] ea d8 [2] d5 c4 }

  condition:
    any of them
}