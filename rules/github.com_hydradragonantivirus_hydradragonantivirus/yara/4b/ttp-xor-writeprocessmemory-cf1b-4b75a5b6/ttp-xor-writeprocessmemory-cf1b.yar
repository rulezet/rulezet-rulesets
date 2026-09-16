rule TTP_XOR_WriteProcessMemory_cf1b {
  strings:
    $key_cf1b = { 98 69 [2] aa 4b [2] ac 7e [2] 82 7e [2] bd 62 }

  condition:
    any of them
}