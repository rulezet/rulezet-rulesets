rule TTP_XOR_WriteProcessMemory_cf4d {
  strings:
    $key_cf4d = { 98 3f [2] aa 1d [2] ac 28 [2] 82 28 [2] bd 34 }

  condition:
    any of them
}