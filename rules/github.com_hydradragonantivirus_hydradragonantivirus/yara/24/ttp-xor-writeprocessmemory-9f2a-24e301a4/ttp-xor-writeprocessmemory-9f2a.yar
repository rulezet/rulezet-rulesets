rule TTP_XOR_WriteProcessMemory_9f2a {
  strings:
    $key_9f2a = { c8 58 [2] fa 7a [2] fc 4f [2] d2 4f [2] ed 53 }

  condition:
    any of them
}