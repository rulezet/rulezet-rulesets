rule TTP_XOR_WriteProcessMemory_cff0 {
  strings:
    $key_cff0 = { 98 82 [2] aa a0 [2] ac 95 [2] 82 95 [2] bd 89 }

  condition:
    any of them
}