rule TTP_XOR_WriteProcessMemory_8eaa {
  strings:
    $key_8eaa = { d9 d8 [2] eb fa [2] ed cf [2] c3 cf [2] fc d3 }

  condition:
    any of them
}