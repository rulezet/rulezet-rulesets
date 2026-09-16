rule TTP_XOR_WriteProcessMemory_cf58 {
  strings:
    $key_cf58 = { 98 2a [2] aa 08 [2] ac 3d [2] 82 3d [2] bd 21 }

  condition:
    any of them
}