rule TTP_XOR_WriteProcessMemory_6caa {
  strings:
    $key_6caa = { 3b d8 [2] 09 fa [2] 0f cf [2] 21 cf [2] 1e d3 }

  condition:
    any of them
}