rule TTP_XOR_WriteProcessMemory_a6aa {
  strings:
    $key_a6aa = { f1 d8 [2] c3 fa [2] c5 cf [2] eb cf [2] d4 d3 }

  condition:
    any of them
}