rule TTP_XOR_WriteProcessMemory_205f {
  strings:
    $key_205f = { 77 2d [2] 45 0f [2] 43 3a [2] 6d 3a [2] 52 26 }

  condition:
    any of them
}