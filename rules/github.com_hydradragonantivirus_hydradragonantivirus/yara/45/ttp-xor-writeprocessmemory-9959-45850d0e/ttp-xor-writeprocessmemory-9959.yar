rule TTP_XOR_WriteProcessMemory_9959 {
  strings:
    $key_9959 = { ce 2b [2] fc 09 [2] fa 3c [2] d4 3c [2] eb 20 }

  condition:
    any of them
}