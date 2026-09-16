rule TTP_XOR_WriteProcessMemory_ebaa {
  strings:
    $key_ebaa = { bc d8 [2] 8e fa [2] 88 cf [2] a6 cf [2] 99 d3 }

  condition:
    any of them
}