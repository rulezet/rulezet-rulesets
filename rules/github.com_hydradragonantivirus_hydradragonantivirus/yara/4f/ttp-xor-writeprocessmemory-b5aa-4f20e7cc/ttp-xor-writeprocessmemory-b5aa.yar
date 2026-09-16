rule TTP_XOR_WriteProcessMemory_b5aa {
  strings:
    $key_b5aa = { e2 d8 [2] d0 fa [2] d6 cf [2] f8 cf [2] c7 d3 }

  condition:
    any of them
}