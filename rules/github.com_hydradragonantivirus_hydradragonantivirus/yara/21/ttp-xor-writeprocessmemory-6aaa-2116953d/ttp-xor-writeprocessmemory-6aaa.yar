rule TTP_XOR_WriteProcessMemory_6aaa {
  strings:
    $key_6aaa = { 3d d8 [2] 0f fa [2] 09 cf [2] 27 cf [2] 18 d3 }

  condition:
    any of them
}