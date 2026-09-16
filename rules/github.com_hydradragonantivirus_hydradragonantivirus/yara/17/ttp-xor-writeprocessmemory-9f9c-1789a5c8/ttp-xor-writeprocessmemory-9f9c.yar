rule TTP_XOR_WriteProcessMemory_9f9c {
  strings:
    $key_9f9c = { c8 ee [2] fa cc [2] fc f9 [2] d2 f9 [2] ed e5 }

  condition:
    any of them
}