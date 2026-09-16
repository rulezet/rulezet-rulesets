rule TTP_XOR_WriteProcessMemory_50aa {
  strings:
    $key_50aa = { 07 d8 [2] 35 fa [2] 33 cf [2] 1d cf [2] 22 d3 }

  condition:
    any of them
}