rule TTP_XOR_WriteProcessMemory_51aa {
  strings:
    $key_51aa = { 06 d8 [2] 34 fa [2] 32 cf [2] 1c cf [2] 23 d3 }

  condition:
    any of them
}