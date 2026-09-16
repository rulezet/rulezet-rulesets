rule TTP_XOR_WriteProcessMemory_cf5e {
  strings:
    $key_cf5e = { 98 2c [2] aa 0e [2] ac 3b [2] 82 3b [2] bd 27 }

  condition:
    any of them
}