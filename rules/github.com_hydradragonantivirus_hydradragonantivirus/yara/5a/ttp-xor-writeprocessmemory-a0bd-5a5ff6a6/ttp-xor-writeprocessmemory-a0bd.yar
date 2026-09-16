rule TTP_XOR_WriteProcessMemory_a0bd {
  strings:
    $key_a0bd = { f7 cf [2] c5 ed [2] c3 d8 [2] ed d8 [2] d2 c4 }

  condition:
    any of them
}