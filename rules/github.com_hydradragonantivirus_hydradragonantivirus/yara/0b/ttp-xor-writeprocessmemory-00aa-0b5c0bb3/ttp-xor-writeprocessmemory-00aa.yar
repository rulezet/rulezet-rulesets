rule TTP_XOR_WriteProcessMemory_00aa {
  strings:
    $key_00aa = { 57 d8 [2] 65 fa [2] 63 cf [2] 4d cf [2] 72 d3 }

  condition:
    any of them
}