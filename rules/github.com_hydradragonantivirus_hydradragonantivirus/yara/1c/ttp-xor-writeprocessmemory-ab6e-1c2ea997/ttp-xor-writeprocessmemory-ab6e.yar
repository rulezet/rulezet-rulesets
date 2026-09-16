rule TTP_XOR_WriteProcessMemory_ab6e {
  strings:
    $key_ab6e = { fc 1c [2] ce 3e [2] c8 0b [2] e6 0b [2] d9 17 }

  condition:
    any of them
}