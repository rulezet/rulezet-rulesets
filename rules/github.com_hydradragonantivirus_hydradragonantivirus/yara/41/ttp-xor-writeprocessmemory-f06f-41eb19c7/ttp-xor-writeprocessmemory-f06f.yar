rule TTP_XOR_WriteProcessMemory_f06f {
  strings:
    $key_f06f = { a7 1d [2] 95 3f [2] 93 0a [2] bd 0a [2] 82 16 }

  condition:
    any of them
}