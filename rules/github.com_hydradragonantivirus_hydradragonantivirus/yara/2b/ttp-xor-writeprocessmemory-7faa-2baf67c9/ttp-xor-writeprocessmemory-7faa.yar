rule TTP_XOR_WriteProcessMemory_7faa {
  strings:
    $key_7faa = { 28 d8 [2] 1a fa [2] 1c cf [2] 32 cf [2] 0d d3 }

  condition:
    any of them
}