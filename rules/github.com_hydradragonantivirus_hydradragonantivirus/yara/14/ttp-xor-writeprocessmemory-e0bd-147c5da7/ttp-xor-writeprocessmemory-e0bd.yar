rule TTP_XOR_WriteProcessMemory_e0bd {
  strings:
    $key_e0bd = { b7 cf [2] 85 ed [2] 83 d8 [2] ad d8 [2] 92 c4 }

  condition:
    any of them
}