rule TTP_XOR_WriteProcessMemory_9f7f {
  strings:
    $key_9f7f = { c8 0d [2] fa 2f [2] fc 1a [2] d2 1a [2] ed 06 }

  condition:
    any of them
}