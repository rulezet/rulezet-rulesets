rule TTP_XOR_WriteProcessMemory_ab55 {
  strings:
    $key_ab55 = { fc 27 [2] ce 05 [2] c8 30 [2] e6 30 [2] d9 2c }

  condition:
    any of them
}