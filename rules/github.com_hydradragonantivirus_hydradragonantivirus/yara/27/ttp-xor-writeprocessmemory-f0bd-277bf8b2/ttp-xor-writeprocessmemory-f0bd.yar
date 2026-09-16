rule TTP_XOR_WriteProcessMemory_f0bd {
  strings:
    $key_f0bd = { a7 cf [2] 95 ed [2] 93 d8 [2] bd d8 [2] 82 c4 }

  condition:
    any of them
}