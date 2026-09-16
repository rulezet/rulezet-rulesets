rule TTP_XOR_WriteProcessMemory_d81e {
  strings:
    $key_d81e = { 8f 6c [2] bd 4e [2] bb 7b [2] 95 7b [2] aa 67 }

  condition:
    any of them
}