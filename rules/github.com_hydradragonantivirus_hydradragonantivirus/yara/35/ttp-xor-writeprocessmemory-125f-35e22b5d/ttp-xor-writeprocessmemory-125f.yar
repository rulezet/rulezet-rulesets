rule TTP_XOR_WriteProcessMemory_125f {
  strings:
    $key_125f = { 45 2d [2] 77 0f [2] 71 3a [2] 5f 3a [2] 60 26 }

  condition:
    any of them
}