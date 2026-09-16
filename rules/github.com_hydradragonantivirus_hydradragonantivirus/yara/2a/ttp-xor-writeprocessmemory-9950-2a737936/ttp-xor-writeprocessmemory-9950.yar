rule TTP_XOR_WriteProcessMemory_9950 {
  strings:
    $key_9950 = { ce 22 [2] fc 00 [2] fa 35 [2] d4 35 [2] eb 29 }

  condition:
    any of them
}