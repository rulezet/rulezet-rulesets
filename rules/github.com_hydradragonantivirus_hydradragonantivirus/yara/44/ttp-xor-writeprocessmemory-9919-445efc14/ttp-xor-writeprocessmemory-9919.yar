rule TTP_XOR_WriteProcessMemory_9919 {
  strings:
    $key_9919 = { ce 6b [2] fc 49 [2] fa 7c [2] d4 7c [2] eb 60 }

  condition:
    any of them
}