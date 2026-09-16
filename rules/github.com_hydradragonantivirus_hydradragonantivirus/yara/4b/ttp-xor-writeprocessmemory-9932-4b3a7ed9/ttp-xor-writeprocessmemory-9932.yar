rule TTP_XOR_WriteProcessMemory_9932 {
  strings:
    $key_9932 = { ce 40 [2] fc 62 [2] fa 57 [2] d4 57 [2] eb 4b }

  condition:
    any of them
}