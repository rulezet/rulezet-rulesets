rule TTP_XOR_WriteProcessMemory_0caa {
  strings:
    $key_0caa = { 5b d8 [2] 69 fa [2] 6f cf [2] 41 cf [2] 7e d3 }

  condition:
    any of them
}