rule TTP_XOR_WriteProcessMemory_4aaa {
  strings:
    $key_4aaa = { 1d d8 [2] 2f fa [2] 29 cf [2] 07 cf [2] 38 d3 }

  condition:
    any of them
}