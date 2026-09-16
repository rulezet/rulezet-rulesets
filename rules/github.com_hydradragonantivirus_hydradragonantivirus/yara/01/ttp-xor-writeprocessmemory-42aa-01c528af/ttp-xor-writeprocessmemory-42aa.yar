rule TTP_XOR_WriteProcessMemory_42aa {
  strings:
    $key_42aa = { 15 d8 [2] 27 fa [2] 21 cf [2] 0f cf [2] 30 d3 }

  condition:
    any of them
}