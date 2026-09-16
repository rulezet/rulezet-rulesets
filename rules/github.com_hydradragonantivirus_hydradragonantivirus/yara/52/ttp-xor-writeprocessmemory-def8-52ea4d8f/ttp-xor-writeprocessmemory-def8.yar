rule TTP_XOR_WriteProcessMemory_def8 {
  strings:
    $key_def8 = { 89 8a [2] bb a8 [2] bd 9d [2] 93 9d [2] ac 81 }

  condition:
    any of them
}