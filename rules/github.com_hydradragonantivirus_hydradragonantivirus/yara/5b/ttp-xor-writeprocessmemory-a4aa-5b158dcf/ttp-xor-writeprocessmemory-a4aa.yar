rule TTP_XOR_WriteProcessMemory_a4aa {
  strings:
    $key_a4aa = { f3 d8 [2] c1 fa [2] c7 cf [2] e9 cf [2] d6 d3 }

  condition:
    any of them
}