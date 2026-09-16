rule TTP_XOR_WriteProcessMemory_ab4c {
  strings:
    $key_ab4c = { fc 3e [2] ce 1c [2] c8 29 [2] e6 29 [2] d9 35 }

  condition:
    any of them
}