rule TTP_XOR_WriteProcessMemory_ab65 {
  strings:
    $key_ab65 = { fc 17 [2] ce 35 [2] c8 00 [2] e6 00 [2] d9 1c }

  condition:
    any of them
}