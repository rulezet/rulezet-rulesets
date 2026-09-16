rule TTP_XOR_WriteProcessMemory_f00f {
  strings:
    $key_f00f = { a7 7d [2] 95 5f [2] 93 6a [2] bd 6a [2] 82 76 }

  condition:
    any of them
}