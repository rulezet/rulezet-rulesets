rule TTP_XOR_WriteProcessMemory_cf4b {
  strings:
    $key_cf4b = { 98 39 [2] aa 1b [2] ac 2e [2] 82 2e [2] bd 32 }

  condition:
    any of them
}