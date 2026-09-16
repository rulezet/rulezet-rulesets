rule TTP_XOR_WriteProcessMemory_963a {
  strings:
    $key_963a = { c1 48 [2] f3 6a [2] f5 5f [2] db 5f [2] e4 43 }

  condition:
    any of them
}