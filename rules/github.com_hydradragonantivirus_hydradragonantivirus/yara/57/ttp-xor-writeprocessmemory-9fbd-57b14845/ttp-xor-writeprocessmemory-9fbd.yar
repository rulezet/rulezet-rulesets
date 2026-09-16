rule TTP_XOR_WriteProcessMemory_9fbd {
  strings:
    $key_9fbd = { c8 cf [2] fa ed [2] fc d8 [2] d2 d8 [2] ed c4 }

  condition:
    any of them
}