rule TTP_XOR_WriteProcessMemory_9f6c {
  strings:
    $key_9f6c = { c8 1e [2] fa 3c [2] fc 09 [2] d2 09 [2] ed 15 }

  condition:
    any of them
}