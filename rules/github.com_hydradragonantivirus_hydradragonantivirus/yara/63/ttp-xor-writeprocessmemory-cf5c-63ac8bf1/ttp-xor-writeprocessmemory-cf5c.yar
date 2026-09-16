rule TTP_XOR_WriteProcessMemory_cf5c {
  strings:
    $key_cf5c = { 98 2e [2] aa 0c [2] ac 39 [2] 82 39 [2] bd 25 }

  condition:
    any of them
}