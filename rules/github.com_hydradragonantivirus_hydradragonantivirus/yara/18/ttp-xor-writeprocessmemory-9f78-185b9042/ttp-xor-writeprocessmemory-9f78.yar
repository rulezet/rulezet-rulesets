rule TTP_XOR_WriteProcessMemory_9f78 {
  strings:
    $key_9f78 = { c8 0a [2] fa 28 [2] fc 1d [2] d2 1d [2] ed 01 }

  condition:
    any of them
}