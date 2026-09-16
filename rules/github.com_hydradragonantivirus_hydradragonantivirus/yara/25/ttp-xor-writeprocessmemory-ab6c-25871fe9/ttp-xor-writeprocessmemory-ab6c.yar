rule TTP_XOR_WriteProcessMemory_ab6c {
  strings:
    $key_ab6c = { fc 1e [2] ce 3c [2] c8 09 [2] e6 09 [2] d9 15 }

  condition:
    any of them
}