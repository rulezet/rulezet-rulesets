rule TTP_XOR_WriteProcessMemory_2caa {
  strings:
    $key_2caa = { 7b d8 [2] 49 fa [2] 4f cf [2] 61 cf [2] 5e d3 }

  condition:
    any of them
}