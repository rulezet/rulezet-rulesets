rule TTP_XOR_WriteProcessMemory_9f1f {
  strings:
    $key_9f1f = { c8 6d [2] fa 4f [2] fc 7a [2] d2 7a [2] ed 66 }

  condition:
    any of them
}