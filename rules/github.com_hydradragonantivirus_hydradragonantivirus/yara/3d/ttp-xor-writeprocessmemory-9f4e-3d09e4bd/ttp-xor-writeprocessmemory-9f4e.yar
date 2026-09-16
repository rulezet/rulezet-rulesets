rule TTP_XOR_WriteProcessMemory_9f4e {
  strings:
    $key_9f4e = { c8 3c [2] fa 1e [2] fc 2b [2] d2 2b [2] ed 37 }

  condition:
    any of them
}