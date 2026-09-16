rule TTP_XOR_WriteProcessMemory_b7aa {
  strings:
    $key_b7aa = { e0 d8 [2] d2 fa [2] d4 cf [2] fa cf [2] c5 d3 }

  condition:
    any of them
}