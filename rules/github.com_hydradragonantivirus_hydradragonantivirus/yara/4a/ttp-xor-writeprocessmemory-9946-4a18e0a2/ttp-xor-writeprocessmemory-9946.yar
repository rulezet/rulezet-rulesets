rule TTP_XOR_WriteProcessMemory_9946 {
  strings:
    $key_9946 = { ce 34 [2] fc 16 [2] fa 23 [2] d4 23 [2] eb 3f }

  condition:
    any of them
}