rule TTP_XOR_WriteProcessMemory_9f7c {
  strings:
    $key_9f7c = { c8 0e [2] fa 2c [2] fc 19 [2] d2 19 [2] ed 05 }

  condition:
    any of them
}