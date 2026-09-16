rule TTP_XOR_WriteProcessMemory_469f {
  strings:
    $key_469f = { 11 ed [2] 23 cf [2] 25 fa [2] 0b fa [2] 34 e6 }

  condition:
    any of them
}