rule TTP_XOR_WriteProcessMemory_58aa {
  strings:
    $key_58aa = { 0f d8 [2] 3d fa [2] 3b cf [2] 15 cf [2] 2a d3 }

  condition:
    any of them
}