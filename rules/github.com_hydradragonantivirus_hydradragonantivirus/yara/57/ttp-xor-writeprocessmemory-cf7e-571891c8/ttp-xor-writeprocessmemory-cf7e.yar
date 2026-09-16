rule TTP_XOR_WriteProcessMemory_cf7e {
  strings:
    $key_cf7e = { 98 0c [2] aa 2e [2] ac 1b [2] 82 1b [2] bd 07 }

  condition:
    any of them
}