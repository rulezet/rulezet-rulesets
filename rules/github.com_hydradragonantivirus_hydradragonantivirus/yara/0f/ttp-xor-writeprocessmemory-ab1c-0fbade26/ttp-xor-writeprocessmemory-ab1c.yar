rule TTP_XOR_WriteProcessMemory_ab1c {
  strings:
    $key_ab1c = { fc 6e [2] ce 4c [2] c8 79 [2] e6 79 [2] d9 65 }

  condition:
    any of them
}