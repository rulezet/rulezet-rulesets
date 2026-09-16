rule TTP_XOR_WriteProcessMemory_9f6d {
  strings:
    $key_9f6d = { c8 1f [2] fa 3d [2] fc 08 [2] d2 08 [2] ed 14 }

  condition:
    any of them
}