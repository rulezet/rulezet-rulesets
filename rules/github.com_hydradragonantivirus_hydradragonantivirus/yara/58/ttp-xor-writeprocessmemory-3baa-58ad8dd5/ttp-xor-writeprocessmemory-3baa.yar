rule TTP_XOR_WriteProcessMemory_3baa {
  strings:
    $key_3baa = { 6c d8 [2] 5e fa [2] 58 cf [2] 76 cf [2] 49 d3 }

  condition:
    any of them
}