rule TTP_XOR_WriteProcessMemory_ab0b {
  strings:
    $key_ab0b = { fc 79 [2] ce 5b [2] c8 6e [2] e6 6e [2] d9 72 }

  condition:
    any of them
}