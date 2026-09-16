rule TTP_XOR_WriteProcessMemory_cf7d {
  strings:
    $key_cf7d = { 98 0f [2] aa 2d [2] ac 18 [2] 82 18 [2] bd 04 }

  condition:
    any of them
}