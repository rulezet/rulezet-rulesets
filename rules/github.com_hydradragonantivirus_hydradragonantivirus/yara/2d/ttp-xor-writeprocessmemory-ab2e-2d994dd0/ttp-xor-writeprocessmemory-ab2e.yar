rule TTP_XOR_WriteProcessMemory_ab2e {
  strings:
    $key_ab2e = { fc 5c [2] ce 7e [2] c8 4b [2] e6 4b [2] d9 57 }

  condition:
    any of them
}