rule TTP_XOR_WriteProcessMemory_ab3b {
  strings:
    $key_ab3b = { fc 49 [2] ce 6b [2] c8 5e [2] e6 5e [2] d9 42 }

  condition:
    any of them
}