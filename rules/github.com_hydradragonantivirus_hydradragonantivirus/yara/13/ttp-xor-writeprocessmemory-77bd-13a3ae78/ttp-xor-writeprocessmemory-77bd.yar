rule TTP_XOR_WriteProcessMemory_77bd {
  strings:
    $key_77bd = { 20 cf [2] 12 ed [2] 14 d8 [2] 3a d8 [2] 05 c4 }

  condition:
    any of them
}