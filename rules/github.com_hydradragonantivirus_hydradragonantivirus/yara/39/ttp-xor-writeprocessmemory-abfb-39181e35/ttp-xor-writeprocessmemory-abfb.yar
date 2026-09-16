rule TTP_XOR_WriteProcessMemory_abfb {
  strings:
    $key_abfb = { fc 89 [2] ce ab [2] c8 9e [2] e6 9e [2] d9 82 }

  condition:
    any of them
}