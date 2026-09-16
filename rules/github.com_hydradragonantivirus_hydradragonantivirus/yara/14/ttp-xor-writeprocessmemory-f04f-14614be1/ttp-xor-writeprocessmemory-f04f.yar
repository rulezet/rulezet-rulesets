rule TTP_XOR_WriteProcessMemory_f04f {
  strings:
    $key_f04f = { a7 3d [2] 95 1f [2] 93 2a [2] bd 2a [2] 82 36 }

  condition:
    any of them
}