rule TTP_XOR_WriteProcessMemory_20aa {
  strings:
    $key_20aa = { 77 d8 [2] 45 fa [2] 43 cf [2] 6d cf [2] 52 d3 }

  condition:
    any of them
}