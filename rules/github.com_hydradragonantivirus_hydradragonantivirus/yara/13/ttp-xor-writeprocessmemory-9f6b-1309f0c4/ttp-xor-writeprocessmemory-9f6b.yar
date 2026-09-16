rule TTP_XOR_WriteProcessMemory_9f6b {
  strings:
    $key_9f6b = { c8 19 [2] fa 3b [2] fc 0e [2] d2 0e [2] ed 12 }

  condition:
    any of them
}