rule TTP_XOR_WriteProcessMemory_feaa {
  strings:
    $key_feaa = { a9 d8 [2] 9b fa [2] 9d cf [2] b3 cf [2] 8c d3 }

  condition:
    any of them
}