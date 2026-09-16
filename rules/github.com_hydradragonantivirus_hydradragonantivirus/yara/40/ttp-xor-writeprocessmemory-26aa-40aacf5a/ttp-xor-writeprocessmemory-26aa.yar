rule TTP_XOR_WriteProcessMemory_26aa {
  strings:
    $key_26aa = { 71 d8 [2] 43 fa [2] 45 cf [2] 6b cf [2] 54 d3 }

  condition:
    any of them
}