rule TTP_XOR_WriteProcessMemory_40aa {
  strings:
    $key_40aa = { 17 d8 [2] 25 fa [2] 23 cf [2] 0d cf [2] 32 d3 }

  condition:
    any of them
}