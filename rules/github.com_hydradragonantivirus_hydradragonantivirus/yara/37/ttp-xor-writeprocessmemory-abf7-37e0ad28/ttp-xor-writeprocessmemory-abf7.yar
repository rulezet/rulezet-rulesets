rule TTP_XOR_WriteProcessMemory_abf7 {
  strings:
    $key_abf7 = { fc 85 [2] ce a7 [2] c8 92 [2] e6 92 [2] d9 8e }

  condition:
    any of them
}