rule TTP_XOR_WriteProcessMemory_ab69 {
  strings:
    $key_ab69 = { fc 1b [2] ce 39 [2] c8 0c [2] e6 0c [2] d9 10 }

  condition:
    any of them
}