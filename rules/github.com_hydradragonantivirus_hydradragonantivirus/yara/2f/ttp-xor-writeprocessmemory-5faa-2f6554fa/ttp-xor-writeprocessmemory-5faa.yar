rule TTP_XOR_WriteProcessMemory_5faa {
  strings:
    $key_5faa = { 08 d8 [2] 3a fa [2] 3c cf [2] 12 cf [2] 2d d3 }

  condition:
    any of them
}