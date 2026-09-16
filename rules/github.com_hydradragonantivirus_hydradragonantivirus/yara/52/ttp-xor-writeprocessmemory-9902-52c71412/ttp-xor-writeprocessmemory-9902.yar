rule TTP_XOR_WriteProcessMemory_9902 {
  strings:
    $key_9902 = { ce 70 [2] fc 52 [2] fa 67 [2] d4 67 [2] eb 7b }

  condition:
    any of them
}