rule TTP_XOR_WriteProcessMemory_f5bd {
  strings:
    $key_f5bd = { a2 cf [2] 90 ed [2] 96 d8 [2] b8 d8 [2] 87 c4 }

  condition:
    any of them
}