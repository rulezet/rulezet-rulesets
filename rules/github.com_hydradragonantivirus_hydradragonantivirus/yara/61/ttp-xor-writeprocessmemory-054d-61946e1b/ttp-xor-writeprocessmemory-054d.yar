rule TTP_XOR_WriteProcessMemory_054d {
  strings:
    $key_054d = { 52 3f [2] 60 1d [2] 66 28 [2] 48 28 [2] 77 34 }

  condition:
    any of them
}