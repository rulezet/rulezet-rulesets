rule TTP_XOR_WriteProcessMemory_cf3e {
  strings:
    $key_cf3e = { 98 4c [2] aa 6e [2] ac 5b [2] 82 5b [2] bd 47 }

  condition:
    any of them
}