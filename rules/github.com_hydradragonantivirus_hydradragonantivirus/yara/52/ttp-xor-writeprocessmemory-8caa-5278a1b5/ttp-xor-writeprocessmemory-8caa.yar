rule TTP_XOR_WriteProcessMemory_8caa {
  strings:
    $key_8caa = { db d8 [2] e9 fa [2] ef cf [2] c1 cf [2] fe d3 }

  condition:
    any of them
}