rule TTP_XOR_WriteProcessMemory_b39f {
  strings:
    $key_b39f = { e4 ed [2] d6 cf [2] d0 fa [2] fe fa [2] c1 e6 }

  condition:
    any of them
}