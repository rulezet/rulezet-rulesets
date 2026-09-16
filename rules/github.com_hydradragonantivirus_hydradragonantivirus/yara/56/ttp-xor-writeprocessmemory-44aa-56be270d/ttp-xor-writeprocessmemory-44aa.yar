rule TTP_XOR_WriteProcessMemory_44aa {
  strings:
    $key_44aa = { 13 d8 [2] 21 fa [2] 27 cf [2] 09 cf [2] 36 d3 }

  condition:
    any of them
}