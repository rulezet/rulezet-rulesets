rule TTP_XOR_WriteProcessMemory_9fca {
  strings:
    $key_9fca = { c8 b8 [2] fa 9a [2] fc af [2] d2 af [2] ed b3 }

  condition:
    any of them
}