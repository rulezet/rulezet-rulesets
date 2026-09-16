rule TTP_XOR_WriteProcessMemory_f03a {
  strings:
    $key_f03a = { a7 48 [2] 95 6a [2] 93 5f [2] bd 5f [2] 82 43 }

  condition:
    any of them
}