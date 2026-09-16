rule TTP_XOR_WriteProcessMemory_9914 {
  strings:
    $key_9914 = { ce 66 [2] fc 44 [2] fa 71 [2] d4 71 [2] eb 6d }

  condition:
    any of them
}