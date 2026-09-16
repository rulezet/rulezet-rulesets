rule TTP_XOR_WriteProcessMemory_9916 {
  strings:
    $key_9916 = { ce 64 [2] fc 46 [2] fa 73 [2] d4 73 [2] eb 6f }

  condition:
    any of them
}