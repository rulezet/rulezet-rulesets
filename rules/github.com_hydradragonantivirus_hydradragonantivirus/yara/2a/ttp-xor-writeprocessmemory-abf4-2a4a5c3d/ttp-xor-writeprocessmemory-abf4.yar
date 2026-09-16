rule TTP_XOR_WriteProcessMemory_abf4 {
  strings:
    $key_abf4 = { fc 86 [2] ce a4 [2] c8 91 [2] e6 91 [2] d9 8d }

  condition:
    any of them
}