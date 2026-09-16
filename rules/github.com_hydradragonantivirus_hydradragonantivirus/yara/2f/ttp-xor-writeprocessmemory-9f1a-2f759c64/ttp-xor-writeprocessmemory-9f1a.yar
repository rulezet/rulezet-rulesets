rule TTP_XOR_WriteProcessMemory_9f1a {
  strings:
    $key_9f1a = { c8 68 [2] fa 4a [2] fc 7f [2] d2 7f [2] ed 63 }

  condition:
    any of them
}