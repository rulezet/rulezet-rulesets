rule TTP_XOR_WriteProcessMemory_caaa {
  strings:
    $key_caaa = { 9d d8 [2] af fa [2] a9 cf [2] 87 cf [2] b8 d3 }

  condition:
    any of them
}