rule TTP_XOR_WriteProcessMemory_a3aa {
  strings:
    $key_a3aa = { f4 d8 [2] c6 fa [2] c0 cf [2] ee cf [2] d1 d3 }

  condition:
    any of them
}