rule TTP_XOR_WriteProcessMemory_9912 {
  strings:
    $key_9912 = { ce 60 [2] fc 42 [2] fa 77 [2] d4 77 [2] eb 6b }

  condition:
    any of them
}