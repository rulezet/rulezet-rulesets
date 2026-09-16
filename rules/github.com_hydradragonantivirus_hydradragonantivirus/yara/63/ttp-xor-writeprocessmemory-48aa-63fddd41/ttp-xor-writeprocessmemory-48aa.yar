rule TTP_XOR_WriteProcessMemory_48aa {
  strings:
    $key_48aa = { 1f d8 [2] 2d fa [2] 2b cf [2] 05 cf [2] 3a d3 }

  condition:
    any of them
}