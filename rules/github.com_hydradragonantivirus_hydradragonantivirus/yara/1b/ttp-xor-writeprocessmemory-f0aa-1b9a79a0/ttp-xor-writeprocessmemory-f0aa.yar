rule TTP_XOR_WriteProcessMemory_f0aa {
  strings:
    $key_f0aa = { a7 d8 [2] 95 fa [2] 93 cf [2] bd cf [2] 82 d3 }

  condition:
    any of them
}