rule TTP_XOR_WriteProcessMemory_9ffc {
  strings:
    $key_9ffc = { c8 8e [2] fa ac [2] fc 99 [2] d2 99 [2] ed 85 }

  condition:
    any of them
}