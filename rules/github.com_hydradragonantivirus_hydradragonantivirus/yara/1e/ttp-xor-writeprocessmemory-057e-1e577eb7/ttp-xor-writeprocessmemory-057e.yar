rule TTP_XOR_WriteProcessMemory_057e {
  strings:
    $key_057e = { 52 0c [2] 60 2e [2] 66 1b [2] 48 1b [2] 77 07 }

  condition:
    any of them
}