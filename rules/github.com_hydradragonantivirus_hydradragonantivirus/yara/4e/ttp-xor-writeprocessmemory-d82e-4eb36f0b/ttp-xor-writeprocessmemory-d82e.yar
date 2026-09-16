rule TTP_XOR_WriteProcessMemory_d82e {
  strings:
    $key_d82e = { 8f 5c [2] bd 7e [2] bb 4b [2] 95 4b [2] aa 57 }

  condition:
    any of them
}