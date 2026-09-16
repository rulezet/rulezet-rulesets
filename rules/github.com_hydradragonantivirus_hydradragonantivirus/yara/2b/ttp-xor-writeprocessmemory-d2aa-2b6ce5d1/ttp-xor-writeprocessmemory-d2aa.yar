rule TTP_XOR_WriteProcessMemory_d2aa {
  strings:
    $key_d2aa = { 85 d8 [2] b7 fa [2] b1 cf [2] 9f cf [2] a0 d3 }

  condition:
    any of them
}