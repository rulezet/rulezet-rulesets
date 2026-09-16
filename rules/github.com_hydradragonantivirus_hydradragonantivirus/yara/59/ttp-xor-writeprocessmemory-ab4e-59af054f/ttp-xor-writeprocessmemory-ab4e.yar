rule TTP_XOR_WriteProcessMemory_ab4e {
  strings:
    $key_ab4e = { fc 3c [2] ce 1e [2] c8 2b [2] e6 2b [2] d9 37 }

  condition:
    any of them
}