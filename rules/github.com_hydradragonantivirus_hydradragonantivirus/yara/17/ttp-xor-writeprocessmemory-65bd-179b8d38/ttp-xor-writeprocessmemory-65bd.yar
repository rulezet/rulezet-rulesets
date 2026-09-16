rule TTP_XOR_WriteProcessMemory_65bd {
  strings:
    $key_65bd = { 32 cf [2] 00 ed [2] 06 d8 [2] 28 d8 [2] 17 c4 }

  condition:
    any of them
}