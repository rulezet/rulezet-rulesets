rule TTP_XOR_WriteProcessMemory_f028 {
  strings:
    $key_f028 = { a7 5a [2] 95 78 [2] 93 4d [2] bd 4d [2] 82 51 }

  condition:
    any of them
}