rule TTP_XOR_WriteProcessMemory_64aa {
  strings:
    $key_64aa = { 33 d8 [2] 01 fa [2] 07 cf [2] 29 cf [2] 16 d3 }

  condition:
    any of them
}