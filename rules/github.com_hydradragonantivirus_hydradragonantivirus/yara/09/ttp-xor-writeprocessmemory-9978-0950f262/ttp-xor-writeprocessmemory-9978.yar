rule TTP_XOR_WriteProcessMemory_9978 {
  strings:
    $key_9978 = { ce 0a [2] fc 28 [2] fa 1d [2] d4 1d [2] eb 01 }

  condition:
    any of them
}