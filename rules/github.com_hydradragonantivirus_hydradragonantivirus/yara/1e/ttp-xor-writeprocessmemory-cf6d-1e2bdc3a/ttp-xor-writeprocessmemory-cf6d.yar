rule TTP_XOR_WriteProcessMemory_cf6d {
  strings:
    $key_cf6d = { 98 1f [2] aa 3d [2] ac 08 [2] 82 08 [2] bd 14 }

  condition:
    any of them
}