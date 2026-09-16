rule TTP_XOR_WriteProcessMemory_9fef {
  strings:
    $key_9fef = { c8 9d [2] fa bf [2] fc 8a [2] d2 8a [2] ed 96 }

  condition:
    any of them
}