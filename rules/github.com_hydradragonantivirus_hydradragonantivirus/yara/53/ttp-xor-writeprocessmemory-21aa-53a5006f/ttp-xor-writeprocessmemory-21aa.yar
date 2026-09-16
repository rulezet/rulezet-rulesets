rule TTP_XOR_WriteProcessMemory_21aa {
  strings:
    $key_21aa = { 76 d8 [2] 44 fa [2] 42 cf [2] 6c cf [2] 53 d3 }

  condition:
    any of them
}