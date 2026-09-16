rule TTP_XOR_WriteProcessMemory_f00a {
  strings:
    $key_f00a = { a7 78 [2] 95 5a [2] 93 6f [2] bd 6f [2] 82 73 }

  condition:
    any of them
}