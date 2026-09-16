rule TTP_XOR_WriteProcessMemory_31aa {
  strings:
    $key_31aa = { 66 d8 [2] 54 fa [2] 52 cf [2] 7c cf [2] 43 d3 }

  condition:
    any of them
}