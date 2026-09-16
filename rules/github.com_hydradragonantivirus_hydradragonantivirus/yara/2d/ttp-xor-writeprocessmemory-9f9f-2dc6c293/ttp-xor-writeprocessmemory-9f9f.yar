rule TTP_XOR_WriteProcessMemory_9f9f {
  strings:
    $key_9f9f = { c8 ed [2] fa cf [2] fc fa [2] d2 fa [2] ed e6 }

  condition:
    any of them
}