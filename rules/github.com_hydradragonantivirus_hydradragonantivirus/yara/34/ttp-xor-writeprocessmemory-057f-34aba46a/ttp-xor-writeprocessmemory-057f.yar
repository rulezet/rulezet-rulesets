rule TTP_XOR_WriteProcessMemory_057f {
  strings:
    $key_057f = { 52 0d [2] 60 2f [2] 66 1a [2] 48 1a [2] 77 06 }

  condition:
    any of them
}