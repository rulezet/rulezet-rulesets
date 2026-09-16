rule TTP_XOR_WriteProcessMemory_dee2 {
  strings:
    $key_dee2 = { 89 90 [2] bb b2 [2] bd 87 [2] 93 87 [2] ac 9b }

  condition:
    any of them
}