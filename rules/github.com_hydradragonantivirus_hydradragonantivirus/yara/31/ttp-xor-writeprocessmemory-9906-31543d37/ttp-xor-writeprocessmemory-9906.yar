rule TTP_XOR_WriteProcessMemory_9906 {
  strings:
    $key_9906 = { ce 74 [2] fc 56 [2] fa 63 [2] d4 63 [2] eb 7f }

  condition:
    any of them
}