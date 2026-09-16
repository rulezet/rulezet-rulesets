rule TTP_XOR_WriteProcessMemory_01bd {
  strings:
    $key_01bd = { 56 cf [2] 64 ed [2] 62 d8 [2] 4c d8 [2] 73 c4 }

  condition:
    any of them
}