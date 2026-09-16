rule TTP_XOR_WriteProcessMemory_2eaa {
  strings:
    $key_2eaa = { 79 d8 [2] 4b fa [2] 4d cf [2] 63 cf [2] 5c d3 }

  condition:
    any of them
}