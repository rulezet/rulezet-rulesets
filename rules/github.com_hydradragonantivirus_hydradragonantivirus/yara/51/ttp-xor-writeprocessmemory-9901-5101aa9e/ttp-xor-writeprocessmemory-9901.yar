rule TTP_XOR_WriteProcessMemory_9901 {
  strings:
    $key_9901 = { ce 73 [2] fc 51 [2] fa 64 [2] d4 64 [2] eb 78 }

  condition:
    any of them
}