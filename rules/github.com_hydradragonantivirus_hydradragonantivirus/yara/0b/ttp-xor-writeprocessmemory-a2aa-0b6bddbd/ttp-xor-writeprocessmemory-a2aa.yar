rule TTP_XOR_WriteProcessMemory_a2aa {
  strings:
    $key_a2aa = { f5 d8 [2] c7 fa [2] c1 cf [2] ef cf [2] d0 d3 }

  condition:
    any of them
}