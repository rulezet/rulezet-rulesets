rule TTP_XOR_WriteProcessMemory_ab63 {
  strings:
    $key_ab63 = { fc 11 [2] ce 33 [2] c8 06 [2] e6 06 [2] d9 1a }

  condition:
    any of them
}