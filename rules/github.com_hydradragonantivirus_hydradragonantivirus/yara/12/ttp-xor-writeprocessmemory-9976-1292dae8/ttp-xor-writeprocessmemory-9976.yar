rule TTP_XOR_WriteProcessMemory_9976 {
  strings:
    $key_9976 = { ce 04 [2] fc 26 [2] fa 13 [2] d4 13 [2] eb 0f }

  condition:
    any of them
}