rule TTP_XOR_WriteProcessMemory_9962 {
  strings:
    $key_9962 = { ce 10 [2] fc 32 [2] fa 07 [2] d4 07 [2] eb 1b }

  condition:
    any of them
}