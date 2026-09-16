rule TTP_XOR_WriteProcessMemory_9926 {
  strings:
    $key_9926 = { ce 54 [2] fc 76 [2] fa 43 [2] d4 43 [2] eb 5f }

  condition:
    any of them
}