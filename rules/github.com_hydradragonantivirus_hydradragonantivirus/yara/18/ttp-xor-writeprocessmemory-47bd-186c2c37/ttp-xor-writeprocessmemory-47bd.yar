rule TTP_XOR_WriteProcessMemory_47bd {
  strings:
    $key_47bd = { 10 cf [2] 22 ed [2] 24 d8 [2] 0a d8 [2] 35 c4 }

  condition:
    any of them
}