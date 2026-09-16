rule TTP_XOR_WriteProcessMemory_c2aa {
  strings:
    $key_c2aa = { 95 d8 [2] a7 fa [2] a1 cf [2] 8f cf [2] b0 d3 }

  condition:
    any of them
}