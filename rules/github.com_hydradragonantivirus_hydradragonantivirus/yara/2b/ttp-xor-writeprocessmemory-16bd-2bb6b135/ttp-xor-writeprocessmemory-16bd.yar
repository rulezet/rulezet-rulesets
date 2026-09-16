rule TTP_XOR_WriteProcessMemory_16bd {
  strings:
    $key_16bd = { 41 cf [2] 73 ed [2] 75 d8 [2] 5b d8 [2] 64 c4 }

  condition:
    any of them
}