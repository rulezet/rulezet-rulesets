rule TTP_XOR_WriteProcessMemory_9929 {
  strings:
    $key_9929 = { ce 5b [2] fc 79 [2] fa 4c [2] d4 4c [2] eb 50 }

  condition:
    any of them
}