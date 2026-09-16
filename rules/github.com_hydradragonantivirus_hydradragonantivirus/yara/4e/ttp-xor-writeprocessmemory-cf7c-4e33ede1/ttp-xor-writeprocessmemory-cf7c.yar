rule TTP_XOR_WriteProcessMemory_cf7c {
  strings:
    $key_cf7c = { 98 0e [2] aa 2c [2] ac 19 [2] 82 19 [2] bd 05 }

  condition:
    any of them
}