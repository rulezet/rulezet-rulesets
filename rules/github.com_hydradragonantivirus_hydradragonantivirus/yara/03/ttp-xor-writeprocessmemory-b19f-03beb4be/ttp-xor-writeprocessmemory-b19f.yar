rule TTP_XOR_WriteProcessMemory_b19f {
  strings:
    $key_b19f = { e6 ed [2] d4 cf [2] d2 fa [2] fc fa [2] c3 e6 }

  condition:
    any of them
}