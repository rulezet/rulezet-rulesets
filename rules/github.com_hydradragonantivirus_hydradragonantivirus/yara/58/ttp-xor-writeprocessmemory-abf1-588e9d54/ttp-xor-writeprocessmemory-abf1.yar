rule TTP_XOR_WriteProcessMemory_abf1 {
  strings:
    $key_abf1 = { fc 83 [2] ce a1 [2] c8 94 [2] e6 94 [2] d9 88 }

  condition:
    any of them
}