rule TTP_XOR_WriteProcessMemory_38aa {
  strings:
    $key_38aa = { 6f d8 [2] 5d fa [2] 5b cf [2] 75 cf [2] 4a d3 }

  condition:
    any of them
}