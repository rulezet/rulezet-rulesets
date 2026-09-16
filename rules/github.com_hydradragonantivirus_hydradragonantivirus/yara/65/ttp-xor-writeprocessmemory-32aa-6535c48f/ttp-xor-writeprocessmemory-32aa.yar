rule TTP_XOR_WriteProcessMemory_32aa {
  strings:
    $key_32aa = { 65 d8 [2] 57 fa [2] 51 cf [2] 7f cf [2] 40 d3 }

  condition:
    any of them
}