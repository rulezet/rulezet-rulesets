rule TTP_XOR_WriteProcessMemory_9fe8 {
  strings:
    $key_9fe8 = { c8 9a [2] fa b8 [2] fc 8d [2] d2 8d [2] ed 91 }

  condition:
    any of them
}