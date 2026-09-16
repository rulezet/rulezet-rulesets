rule TTP_XOR_WriteProcessMemory_9fbb {
  strings:
    $key_9fbb = { c8 c9 [2] fa eb [2] fc de [2] d2 de [2] ed c2 }

  condition:
    any of them
}