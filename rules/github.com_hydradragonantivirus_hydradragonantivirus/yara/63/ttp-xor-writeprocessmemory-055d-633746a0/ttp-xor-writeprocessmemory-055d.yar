rule TTP_XOR_WriteProcessMemory_055d {
  strings:
    $key_055d = { 52 2f [2] 60 0d [2] 66 38 [2] 48 38 [2] 77 24 }

  condition:
    any of them
}