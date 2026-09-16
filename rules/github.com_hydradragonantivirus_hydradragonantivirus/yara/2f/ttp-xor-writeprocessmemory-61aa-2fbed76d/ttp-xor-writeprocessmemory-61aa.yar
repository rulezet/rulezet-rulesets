rule TTP_XOR_WriteProcessMemory_61aa {
  strings:
    $key_61aa = { 36 d8 [2] 04 fa [2] 02 cf [2] 2c cf [2] 13 d3 }

  condition:
    any of them
}