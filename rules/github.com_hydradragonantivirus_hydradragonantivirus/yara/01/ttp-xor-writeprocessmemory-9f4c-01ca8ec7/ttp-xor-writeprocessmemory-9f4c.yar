rule TTP_XOR_WriteProcessMemory_9f4c {
  strings:
    $key_9f4c = { c8 3e [2] fa 1c [2] fc 29 [2] d2 29 [2] ed 35 }

  condition:
    any of them
}