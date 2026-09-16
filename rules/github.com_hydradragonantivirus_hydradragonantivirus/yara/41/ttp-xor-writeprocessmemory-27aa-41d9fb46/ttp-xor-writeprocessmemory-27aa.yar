rule TTP_XOR_WriteProcessMemory_27aa {
  strings:
    $key_27aa = { 70 d8 [2] 42 fa [2] 44 cf [2] 6a cf [2] 55 d3 }

  condition:
    any of them
}