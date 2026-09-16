rule TTP_XOR_WriteProcessMemory_9968 {
  strings:
    $key_9968 = { ce 1a [2] fc 38 [2] fa 0d [2] d4 0d [2] eb 11 }

  condition:
    any of them
}