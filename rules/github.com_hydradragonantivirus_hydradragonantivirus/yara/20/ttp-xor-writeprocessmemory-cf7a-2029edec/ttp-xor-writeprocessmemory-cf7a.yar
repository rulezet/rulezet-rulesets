rule TTP_XOR_WriteProcessMemory_cf7a {
  strings:
    $key_cf7a = { 98 08 [2] aa 2a [2] ac 1f [2] 82 1f [2] bd 03 }

  condition:
    any of them
}