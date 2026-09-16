rule TTP_XOR_WriteProcessMemory_144d {
  strings:
    $key_144d = { 43 3f [2] 71 1d [2] 77 28 [2] 59 28 [2] 66 34 }

  condition:
    any of them
}