rule TTP_XOR_WriteProcessMemory_b59f {
  strings:
    $key_b59f = { e2 ed [2] d0 cf [2] d6 fa [2] f8 fa [2] c7 e6 }

  condition:
    any of them
}