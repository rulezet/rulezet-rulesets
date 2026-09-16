rule TTP_XOR_WriteProcessMemory_375f {
  strings:
    $key_375f = { 60 2d [2] 52 0f [2] 54 3a [2] 7a 3a [2] 45 26 }

  condition:
    any of them
}