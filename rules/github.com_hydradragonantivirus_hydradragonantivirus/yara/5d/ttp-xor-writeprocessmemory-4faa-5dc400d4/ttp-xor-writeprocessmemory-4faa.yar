rule TTP_XOR_WriteProcessMemory_4faa {
  strings:
    $key_4faa = { 18 d8 [2] 2a fa [2] 2c cf [2] 02 cf [2] 3d d3 }

  condition:
    any of them
}