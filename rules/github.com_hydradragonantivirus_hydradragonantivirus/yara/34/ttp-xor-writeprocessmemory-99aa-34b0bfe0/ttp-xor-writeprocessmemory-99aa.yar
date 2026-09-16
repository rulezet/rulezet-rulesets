rule TTP_XOR_WriteProcessMemory_99aa {
  strings:
    $key_99aa = { ce d8 [2] fc fa [2] fa cf [2] d4 cf [2] eb d3 }

  condition:
    any of them
}