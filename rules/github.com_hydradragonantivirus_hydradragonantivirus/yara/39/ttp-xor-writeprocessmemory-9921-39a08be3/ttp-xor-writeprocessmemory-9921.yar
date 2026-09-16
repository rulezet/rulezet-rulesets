rule TTP_XOR_WriteProcessMemory_9921 {
  strings:
    $key_9921 = { ce 53 [2] fc 71 [2] fa 44 [2] d4 44 [2] eb 58 }

  condition:
    any of them
}