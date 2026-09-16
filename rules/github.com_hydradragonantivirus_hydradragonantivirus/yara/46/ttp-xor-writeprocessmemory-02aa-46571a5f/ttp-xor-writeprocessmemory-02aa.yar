rule TTP_XOR_WriteProcessMemory_02aa {
  strings:
    $key_02aa = { 55 d8 [2] 67 fa [2] 61 cf [2] 4f cf [2] 70 d3 }

  condition:
    any of them
}