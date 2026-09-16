rule TTP_XOR_WriteProcessMemory_f9aa {
  strings:
    $key_f9aa = { ae d8 [2] 9c fa [2] 9a cf [2] b4 cf [2] 8b d3 }

  condition:
    any of them
}