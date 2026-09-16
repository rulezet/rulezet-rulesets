rule TTP_XOR_WriteProcessMemory_9f1c {
  strings:
    $key_9f1c = { c8 6e [2] fa 4c [2] fc 79 [2] d2 79 [2] ed 65 }

  condition:
    any of them
}