rule TTP_XOR_WriteProcessMemory_cff2 {
  strings:
    $key_cff2 = { 98 80 [2] aa a2 [2] ac 97 [2] 82 97 [2] bd 8b }

  condition:
    any of them
}