rule TTP_XOR_WriteProcessMemory_63aa {
  strings:
    $key_63aa = { 34 d8 [2] 06 fa [2] 00 cf [2] 2e cf [2] 11 d3 }

  condition:
    any of them
}