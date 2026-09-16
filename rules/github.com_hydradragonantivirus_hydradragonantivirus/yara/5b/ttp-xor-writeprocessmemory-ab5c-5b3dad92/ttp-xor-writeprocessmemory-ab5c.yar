rule TTP_XOR_WriteProcessMemory_ab5c {
  strings:
    $key_ab5c = { fc 2e [2] ce 0c [2] c8 39 [2] e6 39 [2] d9 25 }

  condition:
    any of them
}