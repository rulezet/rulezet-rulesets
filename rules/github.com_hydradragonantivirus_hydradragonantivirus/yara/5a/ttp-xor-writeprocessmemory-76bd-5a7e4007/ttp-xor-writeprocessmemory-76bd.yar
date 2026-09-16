rule TTP_XOR_WriteProcessMemory_76bd {
  strings:
    $key_76bd = { 21 cf [2] 13 ed [2] 15 d8 [2] 3b d8 [2] 04 c4 }

  condition:
    any of them
}