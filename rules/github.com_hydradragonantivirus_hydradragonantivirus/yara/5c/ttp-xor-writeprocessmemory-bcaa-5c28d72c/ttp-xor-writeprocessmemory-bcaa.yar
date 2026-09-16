rule TTP_XOR_WriteProcessMemory_bcaa {
  strings:
    $key_bcaa = { eb d8 [2] d9 fa [2] df cf [2] f1 cf [2] ce d3 }

  condition:
    any of them
}