rule TTP_XOR_WriteProcessMemory_4eaa {
  strings:
    $key_4eaa = { 19 d8 [2] 2b fa [2] 2d cf [2] 03 cf [2] 3c d3 }

  condition:
    any of them
}