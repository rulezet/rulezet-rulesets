rule TTP_XOR_WriteProcessMemory_a0aa {
  strings:
    $key_a0aa = { f7 d8 [2] c5 fa [2] c3 cf [2] ed cf [2] d2 d3 }

  condition:
    any of them
}