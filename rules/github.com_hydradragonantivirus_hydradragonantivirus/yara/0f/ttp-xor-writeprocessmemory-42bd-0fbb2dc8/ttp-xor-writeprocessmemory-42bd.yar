rule TTP_XOR_WriteProcessMemory_42bd {
  strings:
    $key_42bd = { 15 cf [2] 27 ed [2] 21 d8 [2] 0f d8 [2] 30 c4 }

  condition:
    any of them
}