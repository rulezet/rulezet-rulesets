rule TTP_XOR_WriteProcessMemory_a4bd {
  strings:
    $key_a4bd = { f3 cf [2] c1 ed [2] c7 d8 [2] e9 d8 [2] d6 c4 }

  condition:
    any of them
}