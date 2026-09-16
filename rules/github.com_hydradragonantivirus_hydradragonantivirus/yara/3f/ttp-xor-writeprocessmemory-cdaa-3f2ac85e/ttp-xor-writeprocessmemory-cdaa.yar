rule TTP_XOR_WriteProcessMemory_cdaa {
  strings:
    $key_cdaa = { 9a d8 [2] a8 fa [2] ae cf [2] 80 cf [2] bf d3 }

  condition:
    any of them
}