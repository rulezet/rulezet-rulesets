rule TTP_XOR_WriteProcessMemory_ab1b {
  strings:
    $key_ab1b = { fc 69 [2] ce 4b [2] c8 7e [2] e6 7e [2] d9 62 }

  condition:
    any of them
}