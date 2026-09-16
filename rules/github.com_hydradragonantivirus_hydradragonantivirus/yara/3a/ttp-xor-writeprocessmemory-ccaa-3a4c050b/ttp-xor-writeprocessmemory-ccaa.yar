rule TTP_XOR_WriteProcessMemory_ccaa {
  strings:
    $key_ccaa = { 9b d8 [2] a9 fa [2] af cf [2] 81 cf [2] be d3 }

  condition:
    any of them
}