rule TTP_XOR_WriteProcessMemory_cff9 {
  strings:
    $key_cff9 = { 98 8b [2] aa a9 [2] ac 9c [2] 82 9c [2] bd 80 }

  condition:
    any of them
}