rule TTP_XOR_WriteProcessMemory_def7 {
  strings:
    $key_def7 = { 89 85 [2] bb a7 [2] bd 92 [2] 93 92 [2] ac 8e }

  condition:
    any of them
}