rule TTP_XOR_WriteProcessMemory_125d {
  strings:
    $key_125d = { 45 2f [2] 77 0d [2] 71 38 [2] 5f 38 [2] 60 24 }

  condition:
    any of them
}