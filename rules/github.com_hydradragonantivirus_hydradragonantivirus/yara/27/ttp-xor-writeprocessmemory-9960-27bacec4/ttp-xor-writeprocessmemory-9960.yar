rule TTP_XOR_WriteProcessMemory_9960 {
  strings:
    $key_9960 = { ce 12 [2] fc 30 [2] fa 05 [2] d4 05 [2] eb 19 }

  condition:
    any of them
}