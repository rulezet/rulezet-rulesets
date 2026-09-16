rule TTP_XOR_WriteProcessMemory_374d {
  strings:
    $key_374d = { 60 3f [2] 52 1d [2] 54 28 [2] 7a 28 [2] 45 34 }

  condition:
    any of them
}