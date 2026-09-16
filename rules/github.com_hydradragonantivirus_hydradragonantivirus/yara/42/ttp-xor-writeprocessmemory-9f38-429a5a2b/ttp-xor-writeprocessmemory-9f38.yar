rule TTP_XOR_WriteProcessMemory_9f38 {
  strings:
    $key_9f38 = { c8 4a [2] fa 68 [2] fc 5d [2] d2 5d [2] ed 41 }

  condition:
    any of them
}