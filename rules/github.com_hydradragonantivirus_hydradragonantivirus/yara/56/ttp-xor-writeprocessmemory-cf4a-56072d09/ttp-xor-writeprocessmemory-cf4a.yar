rule TTP_XOR_WriteProcessMemory_cf4a {
  strings:
    $key_cf4a = { 98 38 [2] aa 1a [2] ac 2f [2] 82 2f [2] bd 33 }

  condition:
    any of them
}