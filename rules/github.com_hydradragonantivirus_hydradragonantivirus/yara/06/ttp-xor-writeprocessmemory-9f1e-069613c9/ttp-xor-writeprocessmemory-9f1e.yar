rule TTP_XOR_WriteProcessMemory_9f1e {
  strings:
    $key_9f1e = { c8 6c [2] fa 4e [2] fc 7b [2] d2 7b [2] ed 67 }

  condition:
    any of them
}