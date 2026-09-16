rule TTP_XOR_WriteProcessMemory_9940 {
  strings:
    $key_9940 = { ce 32 [2] fc 10 [2] fa 25 [2] d4 25 [2] eb 39 }

  condition:
    any of them
}