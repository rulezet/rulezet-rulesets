rule TTP_XOR_WriteProcessMemory_9955 {
  strings:
    $key_9955 = { ce 27 [2] fc 05 [2] fa 30 [2] d4 30 [2] eb 2c }

  condition:
    any of them
}