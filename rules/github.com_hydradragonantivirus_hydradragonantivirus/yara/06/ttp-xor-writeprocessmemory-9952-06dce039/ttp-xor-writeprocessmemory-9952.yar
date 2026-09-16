rule TTP_XOR_WriteProcessMemory_9952 {
  strings:
    $key_9952 = { ce 20 [2] fc 02 [2] fa 37 [2] d4 37 [2] eb 2b }

  condition:
    any of them
}