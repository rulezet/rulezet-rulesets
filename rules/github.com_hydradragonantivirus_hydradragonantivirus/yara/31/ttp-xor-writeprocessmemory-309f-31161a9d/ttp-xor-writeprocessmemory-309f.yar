rule TTP_XOR_WriteProcessMemory_309f {
  strings:
    $key_309f = { 67 ed [2] 55 cf [2] 53 fa [2] 7d fa [2] 42 e6 }

  condition:
    any of them
}