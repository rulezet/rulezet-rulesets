rule TTP_XOR_WriteProcessMemory_cfaa {
  strings:
    $key_cfaa = { 98 d8 [2] aa fa [2] ac cf [2] 82 cf [2] bd d3 }

  condition:
    any of them
}