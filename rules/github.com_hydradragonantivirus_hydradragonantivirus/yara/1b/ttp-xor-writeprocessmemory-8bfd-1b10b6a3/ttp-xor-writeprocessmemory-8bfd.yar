rule TTP_XOR_WriteProcessMemory_8bfd {
  strings:
    $key_8bfd = { dc 8f [2] ee ad [2] e8 98 [2] c6 98 [2] f9 84 }

  condition:
    any of them
}