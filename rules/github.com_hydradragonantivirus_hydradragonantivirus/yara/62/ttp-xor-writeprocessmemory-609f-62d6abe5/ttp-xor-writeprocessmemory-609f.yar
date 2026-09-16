rule TTP_XOR_WriteProcessMemory_609f {
  strings:
    $key_609f = { 37 ed [2] 05 cf [2] 03 fa [2] 2d fa [2] 12 e6 }

  condition:
    any of them
}