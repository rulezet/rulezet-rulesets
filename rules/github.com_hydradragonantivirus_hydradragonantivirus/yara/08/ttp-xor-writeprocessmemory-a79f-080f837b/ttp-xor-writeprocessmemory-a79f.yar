rule TTP_XOR_WriteProcessMemory_a79f {
  strings:
    $key_a79f = { f0 ed [2] c2 cf [2] c4 fa [2] ea fa [2] d5 e6 }

  condition:
    any of them
}