rule TTP_XOR_WriteProcessMemory_53aa {
  strings:
    $key_53aa = { 04 d8 [2] 36 fa [2] 30 cf [2] 1e cf [2] 21 d3 }

  condition:
    any of them
}