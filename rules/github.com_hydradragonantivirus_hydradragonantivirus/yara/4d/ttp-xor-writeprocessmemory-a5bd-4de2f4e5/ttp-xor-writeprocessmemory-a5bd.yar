rule TTP_XOR_WriteProcessMemory_a5bd {
  strings:
    $key_a5bd = { f2 cf [2] c0 ed [2] c6 d8 [2] e8 d8 [2] d7 c4 }

  condition:
    any of them
}