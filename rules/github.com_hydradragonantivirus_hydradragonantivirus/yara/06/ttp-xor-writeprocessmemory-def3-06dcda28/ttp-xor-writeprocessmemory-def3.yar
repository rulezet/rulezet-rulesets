rule TTP_XOR_WriteProcessMemory_def3 {
  strings:
    $key_def3 = { 89 81 [2] bb a3 [2] bd 96 [2] 93 96 [2] ac 8a }

  condition:
    any of them
}