rule TTP_XOR_WriteProcessMemory_9973 {
  strings:
    $key_9973 = { ce 01 [2] fc 23 [2] fa 16 [2] d4 16 [2] eb 0a }

  condition:
    any of them
}