rule TTP_XOR_WriteProcessMemory_d3aa {
  strings:
    $key_d3aa = { 84 d8 [2] b6 fa [2] b0 cf [2] 9e cf [2] a1 d3 }

  condition:
    any of them
}