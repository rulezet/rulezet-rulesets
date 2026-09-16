rule TTP_XOR_WriteProcessMemory_fbaa {
  strings:
    $key_fbaa = { ac d8 [2] 9e fa [2] 98 cf [2] b6 cf [2] 89 d3 }

  condition:
    any of them
}