rule TTP_XOR_WriteProcessMemory_abfc {
  strings:
    $key_abfc = { fc 8e [2] ce ac [2] c8 99 [2] e6 99 [2] d9 85 }

  condition:
    any of them
}