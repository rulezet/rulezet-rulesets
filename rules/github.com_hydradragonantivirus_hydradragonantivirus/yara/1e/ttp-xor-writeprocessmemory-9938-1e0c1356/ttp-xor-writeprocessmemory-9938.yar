rule TTP_XOR_WriteProcessMemory_9938 {
  strings:
    $key_9938 = { ce 4a [2] fc 68 [2] fa 5d [2] d4 5d [2] eb 41 }

  condition:
    any of them
}