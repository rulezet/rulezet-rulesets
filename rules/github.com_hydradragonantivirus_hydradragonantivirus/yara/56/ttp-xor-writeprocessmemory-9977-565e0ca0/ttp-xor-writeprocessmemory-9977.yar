rule TTP_XOR_WriteProcessMemory_9977 {
  strings:
    $key_9977 = { ce 05 [2] fc 27 [2] fa 12 [2] d4 12 [2] eb 0e }

  condition:
    any of them
}