rule TTP_XOR_WriteProcessMemory_07bd {
  strings:
    $key_07bd = { 50 cf [2] 62 ed [2] 64 d8 [2] 4a d8 [2] 75 c4 }

  condition:
    any of them
}