rule TTP_XOR_WriteProcessMemory_9f6e {
  strings:
    $key_9f6e = { c8 1c [2] fa 3e [2] fc 0b [2] d2 0b [2] ed 17 }

  condition:
    any of them
}