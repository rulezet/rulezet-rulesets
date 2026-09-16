rule TTP_XOR_WriteProcessMemory_479f {
  strings:
    $key_479f = { 10 ed [2] 22 cf [2] 24 fa [2] 0a fa [2] 35 e6 }

  condition:
    any of them
}