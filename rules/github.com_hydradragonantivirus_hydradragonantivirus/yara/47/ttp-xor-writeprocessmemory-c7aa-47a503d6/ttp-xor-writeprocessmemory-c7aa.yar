rule TTP_XOR_WriteProcessMemory_c7aa {
  strings:
    $key_c7aa = { 90 d8 [2] a2 fa [2] a4 cf [2] 8a cf [2] b5 d3 }

  condition:
    any of them
}