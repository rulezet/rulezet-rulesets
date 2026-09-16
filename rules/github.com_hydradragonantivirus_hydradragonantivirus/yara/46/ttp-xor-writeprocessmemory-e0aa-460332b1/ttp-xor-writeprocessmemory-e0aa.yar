rule TTP_XOR_WriteProcessMemory_e0aa {
  strings:
    $key_e0aa = { b7 d8 [2] 85 fa [2] 83 cf [2] ad cf [2] 92 d3 }

  condition:
    any of them
}