rule TTP_XOR_WriteProcessMemory_e7aa {
  strings:
    $key_e7aa = { b0 d8 [2] 82 fa [2] 84 cf [2] aa cf [2] 95 d3 }

  condition:
    any of them
}