rule TTP_XOR_WriteProcessMemory_374b {
  strings:
    $key_374b = { 60 39 [2] 52 1b [2] 54 2e [2] 7a 2e [2] 45 32 }

  condition:
    any of them
}