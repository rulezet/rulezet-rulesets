rule TTP_XOR_WriteProcessMemory_9958 {
  strings:
    $key_9958 = { ce 2a [2] fc 08 [2] fa 3d [2] d4 3d [2] eb 21 }

  condition:
    any of them
}