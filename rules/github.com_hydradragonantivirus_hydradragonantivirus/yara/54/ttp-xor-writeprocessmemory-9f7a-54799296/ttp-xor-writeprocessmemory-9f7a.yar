rule TTP_XOR_WriteProcessMemory_9f7a {
  strings:
    $key_9f7a = { c8 08 [2] fa 2a [2] fc 1f [2] d2 1f [2] ed 03 }

  condition:
    any of them
}