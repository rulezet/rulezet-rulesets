rule TTP_XOR_WriteProcessMemory_0daa {
  strings:
    $key_0daa = { 5a d8 [2] 68 fa [2] 6e cf [2] 40 cf [2] 7f d3 }

  condition:
    any of them
}