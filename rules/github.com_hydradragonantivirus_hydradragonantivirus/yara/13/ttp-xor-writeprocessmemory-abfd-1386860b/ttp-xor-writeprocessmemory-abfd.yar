rule TTP_XOR_WriteProcessMemory_abfd {
  strings:
    $key_abfd = { fc 8f [2] ce ad [2] c8 98 [2] e6 98 [2] d9 84 }

  condition:
    any of them
}