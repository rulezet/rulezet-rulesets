rule TTP_XOR_WriteProcessMemory_a2bd {
  strings:
    $key_a2bd = { f5 cf [2] c7 ed [2] c1 d8 [2] ef d8 [2] d0 c4 }

  condition:
    any of them
}