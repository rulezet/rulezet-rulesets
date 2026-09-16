rule TTP_XOR_WriteProcessMemory_f3aa {
  strings:
    $key_f3aa = { a4 d8 [2] 96 fa [2] 90 cf [2] be cf [2] 81 d3 }

  condition:
    any of them
}