rule TTP_XOR_WriteProcessMemory_9f3c {
  strings:
    $key_9f3c = { c8 4e [2] fa 6c [2] fc 59 [2] d2 59 [2] ed 45 }

  condition:
    any of them
}