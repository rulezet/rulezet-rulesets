rule TTP_XOR_WriteProcessMemory_cfeb {
  strings:
    $key_cfeb = { 98 99 [2] aa bb [2] ac 8e [2] 82 8e [2] bd 92 }

  condition:
    any of them
}