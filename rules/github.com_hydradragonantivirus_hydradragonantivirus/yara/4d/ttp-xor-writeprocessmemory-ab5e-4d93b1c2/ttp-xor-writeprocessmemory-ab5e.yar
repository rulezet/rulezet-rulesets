rule TTP_XOR_WriteProcessMemory_ab5e {
  strings:
    $key_ab5e = { fc 2c [2] ce 0e [2] c8 3b [2] e6 3b [2] d9 27 }

  condition:
    any of them
}