rule TTP_XOR_WriteProcessMemory_30aa {
  strings:
    $key_30aa = { 67 d8 [2] 55 fa [2] 53 cf [2] 7d cf [2] 42 d3 }

  condition:
    any of them
}