rule TTP_XOR_WriteProcessMemory_d0aa {
  strings:
    $key_d0aa = { 87 d8 [2] b5 fa [2] b3 cf [2] 9d cf [2] a2 d3 }

  condition:
    any of them
}