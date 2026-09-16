rule TTP_XOR_WriteProcessMemory_ab50 {
  strings:
    $key_ab50 = { fc 22 [2] ce 00 [2] c8 35 [2] e6 35 [2] d9 29 }

  condition:
    any of them
}