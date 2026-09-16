rule TTP_XOR_WriteProcessMemory_a59f {
  strings:
    $key_a59f = { f2 ed [2] c0 cf [2] c6 fa [2] e8 fa [2] d7 e6 }

  condition:
    any of them
}