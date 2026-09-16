rule TTP_XOR_WriteProcessMemory_cf2d {
  strings:
    $key_cf2d = { 98 5f [2] aa 7d [2] ac 48 [2] 82 48 [2] bd 54 }

  condition:
    any of them
}