rule TTP_XOR_WriteProcessMemory_e6bd {
  strings:
    $key_e6bd = { b1 cf [2] 83 ed [2] 85 d8 [2] ab d8 [2] 94 c4 }

  condition:
    any of them
}