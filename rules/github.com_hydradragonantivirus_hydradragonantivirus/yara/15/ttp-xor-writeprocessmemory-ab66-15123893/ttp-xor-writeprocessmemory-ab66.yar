rule TTP_XOR_WriteProcessMemory_ab66 {
  strings:
    $key_ab66 = { fc 14 [2] ce 36 [2] c8 03 [2] e6 03 [2] d9 1f }

  condition:
    any of them
}