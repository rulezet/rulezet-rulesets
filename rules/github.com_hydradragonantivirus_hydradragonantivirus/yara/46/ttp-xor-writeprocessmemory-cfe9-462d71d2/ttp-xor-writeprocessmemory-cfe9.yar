rule TTP_XOR_WriteProcessMemory_cfe9 {
  strings:
    $key_cfe9 = { 98 9b [2] aa b9 [2] ac 8c [2] 82 8c [2] bd 90 }

  condition:
    any of them
}