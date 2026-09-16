rule TTP_XOR_WriteProcessMemory_cf18 {
  strings:
    $key_cf18 = { 98 6a [2] aa 48 [2] ac 7d [2] 82 7d [2] bd 61 }

  condition:
    any of them
}