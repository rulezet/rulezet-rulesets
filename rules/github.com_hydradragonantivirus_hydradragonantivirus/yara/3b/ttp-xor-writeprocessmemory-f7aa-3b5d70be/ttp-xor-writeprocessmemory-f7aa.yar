rule TTP_XOR_WriteProcessMemory_f7aa {
  strings:
    $key_f7aa = { a0 d8 [2] 92 fa [2] 94 cf [2] ba cf [2] 85 d3 }

  condition:
    any of them
}