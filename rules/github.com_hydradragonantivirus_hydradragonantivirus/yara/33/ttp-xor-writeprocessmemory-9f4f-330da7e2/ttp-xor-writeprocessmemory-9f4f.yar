rule TTP_XOR_WriteProcessMemory_9f4f {
  strings:
    $key_9f4f = { c8 3d [2] fa 1f [2] fc 2a [2] d2 2a [2] ed 36 }

  condition:
    any of them
}