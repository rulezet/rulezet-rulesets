rule TTP_XOR_WriteProcessMemory_055f {
  strings:
    $key_055f = { 52 2d [2] 60 0f [2] 66 3a [2] 48 3a [2] 77 26 }

  condition:
    any of them
}