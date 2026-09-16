rule TTP_XOR_WriteProcessMemory_56aa {
  strings:
    $key_56aa = { 01 d8 [2] 33 fa [2] 35 cf [2] 1b cf [2] 24 d3 }

  condition:
    any of them
}