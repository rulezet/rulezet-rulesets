rule TTP_XOR_WriteProcessMemory_cf44 {
  strings:
    $key_cf44 = { 98 36 [2] aa 14 [2] ac 21 [2] 82 21 [2] bd 3d }

  condition:
    any of them
}