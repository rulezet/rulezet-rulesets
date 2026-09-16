rule TTP_XOR_WriteProcessMemory_aeaa {
  strings:
    $key_aeaa = { f9 d8 [2] cb fa [2] cd cf [2] e3 cf [2] dc d3 }

  condition:
    any of them
}