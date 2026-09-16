rule TTP_XOR_WriteProcessMemory_9f2c {
  strings:
    $key_9f2c = { c8 5e [2] fa 7c [2] fc 49 [2] d2 49 [2] ed 55 }

  condition:
    any of them
}