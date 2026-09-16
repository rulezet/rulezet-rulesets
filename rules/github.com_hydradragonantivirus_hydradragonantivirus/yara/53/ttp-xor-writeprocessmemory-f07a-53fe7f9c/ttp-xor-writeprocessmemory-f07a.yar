rule TTP_XOR_WriteProcessMemory_f07a {
  strings:
    $key_f07a = { a7 08 [2] 95 2a [2] 93 1f [2] bd 1f [2] 82 03 }

  condition:
    any of them
}