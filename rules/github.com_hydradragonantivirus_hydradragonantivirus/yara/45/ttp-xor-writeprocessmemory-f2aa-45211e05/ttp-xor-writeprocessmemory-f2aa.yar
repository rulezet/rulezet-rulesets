rule TTP_XOR_WriteProcessMemory_f2aa {
  strings:
    $key_f2aa = { a5 d8 [2] 97 fa [2] 91 cf [2] bf cf [2] 80 d3 }

  condition:
    any of them
}