rule TTP_XOR_WriteProcessMemory_cf6c {
  strings:
    $key_cf6c = { 98 1e [2] aa 3c [2] ac 09 [2] 82 09 [2] bd 15 }

  condition:
    any of them
}