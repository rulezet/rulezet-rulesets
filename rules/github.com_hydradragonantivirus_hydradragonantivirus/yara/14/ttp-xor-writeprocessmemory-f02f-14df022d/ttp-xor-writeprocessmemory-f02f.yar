rule TTP_XOR_WriteProcessMemory_f02f {
  strings:
    $key_f02f = { a7 5d [2] 95 7f [2] 93 4a [2] bd 4a [2] 82 56 }

  condition:
    any of them
}