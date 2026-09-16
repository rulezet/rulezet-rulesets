rule TTP_XOR_WriteProcessMemory_9f58 {
  strings:
    $key_9f58 = { c8 2a [2] fa 08 [2] fc 3d [2] d2 3d [2] ed 21 }

  condition:
    any of them
}