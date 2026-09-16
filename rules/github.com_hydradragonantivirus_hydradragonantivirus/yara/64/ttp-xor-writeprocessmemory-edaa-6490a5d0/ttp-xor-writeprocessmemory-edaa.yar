rule TTP_XOR_WriteProcessMemory_edaa {
  strings:
    $key_edaa = { ba d8 [2] 88 fa [2] 8e cf [2] a0 cf [2] 9f d3 }

  condition:
    any of them
}