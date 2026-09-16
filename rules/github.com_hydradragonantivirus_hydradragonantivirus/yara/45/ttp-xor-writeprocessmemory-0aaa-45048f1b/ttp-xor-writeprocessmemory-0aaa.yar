rule TTP_XOR_WriteProcessMemory_0aaa {
  strings:
    $key_0aaa = { 5d d8 [2] 6f fa [2] 69 cf [2] 47 cf [2] 78 d3 }

  condition:
    any of them
}