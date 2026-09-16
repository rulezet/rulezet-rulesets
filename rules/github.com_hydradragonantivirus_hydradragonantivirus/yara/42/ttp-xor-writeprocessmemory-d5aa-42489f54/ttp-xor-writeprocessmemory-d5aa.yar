rule TTP_XOR_WriteProcessMemory_d5aa {
  strings:
    $key_d5aa = { 82 d8 [2] b0 fa [2] b6 cf [2] 98 cf [2] a7 d3 }

  condition:
    any of them
}