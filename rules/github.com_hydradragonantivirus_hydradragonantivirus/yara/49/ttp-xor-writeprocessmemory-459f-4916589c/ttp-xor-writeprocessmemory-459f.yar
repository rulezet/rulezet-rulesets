rule TTP_XOR_WriteProcessMemory_459f {
  strings:
    $key_459f = { 12 ed [2] 20 cf [2] 26 fa [2] 08 fa [2] 37 e6 }

  condition:
    any of them
}