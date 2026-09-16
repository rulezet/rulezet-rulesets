rule TTP_XOR_WriteProcessMemory_3eaa {
  strings:
    $key_3eaa = { 69 d8 [2] 5b fa [2] 5d cf [2] 73 cf [2] 4c d3 }

  condition:
    any of them
}