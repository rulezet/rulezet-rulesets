rule TTP_XOR_WriteProcessMemory_9f18 {
  strings:
    $key_9f18 = { c8 6a [2] fa 48 [2] fc 7d [2] d2 7d [2] ed 61 }

  condition:
    any of them
}