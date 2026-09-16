rule TTP_XOR_WriteProcessMemory_9f2e {
  strings:
    $key_9f2e = { c8 5c [2] fa 7e [2] fc 4b [2] d2 4b [2] ed 57 }

  condition:
    any of them
}