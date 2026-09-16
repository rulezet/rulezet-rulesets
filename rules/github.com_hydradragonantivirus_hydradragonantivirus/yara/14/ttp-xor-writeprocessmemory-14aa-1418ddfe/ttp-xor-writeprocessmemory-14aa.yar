rule TTP_XOR_WriteProcessMemory_14aa {
  strings:
    $key_14aa = { 43 d8 [2] 71 fa [2] 77 cf [2] 59 cf [2] 66 d3 }

  condition:
    any of them
}