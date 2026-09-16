rule TTP_XOR_WriteProcessMemory_9972 {
  strings:
    $key_9972 = { ce 00 [2] fc 22 [2] fa 17 [2] d4 17 [2] eb 0b }

  condition:
    any of them
}