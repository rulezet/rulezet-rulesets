rule TTP_XOR_WriteProcessMemory_cfed {
  strings:
    $key_cfed = { 98 9f [2] aa bd [2] ac 88 [2] 82 88 [2] bd 94 }

  condition:
    any of them
}