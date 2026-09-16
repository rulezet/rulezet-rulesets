rule TTP_XOR_WriteProcessMemory_9f3b {
  strings:
    $key_9f3b = { c8 49 [2] fa 6b [2] fc 5e [2] d2 5e [2] ed 42 }

  condition:
    any of them
}