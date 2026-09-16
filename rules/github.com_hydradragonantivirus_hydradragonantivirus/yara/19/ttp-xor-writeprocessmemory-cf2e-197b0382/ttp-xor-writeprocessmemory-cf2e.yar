rule TTP_XOR_WriteProcessMemory_cf2e {
  strings:
    $key_cf2e = { 98 5c [2] aa 7e [2] ac 4b [2] 82 4b [2] bd 57 }

  condition:
    any of them
}