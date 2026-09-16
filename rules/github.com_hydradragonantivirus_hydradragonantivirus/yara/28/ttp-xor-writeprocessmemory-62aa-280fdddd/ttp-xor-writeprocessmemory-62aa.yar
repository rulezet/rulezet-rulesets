rule TTP_XOR_WriteProcessMemory_62aa {
  strings:
    $key_62aa = { 35 d8 [2] 07 fa [2] 01 cf [2] 2f cf [2] 10 d3 }

  condition:
    any of them
}