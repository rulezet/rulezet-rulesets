rule TTP_XOR_WriteProcessMemory_02bd {
  strings:
    $key_02bd = { 55 cf [2] 67 ed [2] 61 d8 [2] 4f d8 [2] 70 c4 }

  condition:
    any of them
}