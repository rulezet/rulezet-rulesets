rule TTP_XOR_WriteProcessMemory_37bd {
  strings:
    $key_37bd = { 60 cf [2] 52 ed [2] 54 d8 [2] 7a d8 [2] 45 c4 }

  condition:
    any of them
}