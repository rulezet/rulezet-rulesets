rule TTP_XOR_WriteProcessMemory_def9 {
  strings:
    $key_def9 = { 89 8b [2] bb a9 [2] bd 9c [2] 93 9c [2] ac 80 }

  condition:
    any of them
}