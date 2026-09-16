rule TTP_XOR_WriteProcessMemory_f8aa {
  strings:
    $key_f8aa = { af d8 [2] 9d fa [2] 9b cf [2] b5 cf [2] 8a d3 }

  condition:
    any of them
}