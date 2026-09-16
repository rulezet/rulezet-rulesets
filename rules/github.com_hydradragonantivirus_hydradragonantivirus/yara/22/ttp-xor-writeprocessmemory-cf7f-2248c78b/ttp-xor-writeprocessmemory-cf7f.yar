rule TTP_XOR_WriteProcessMemory_cf7f {
  strings:
    $key_cf7f = { 98 0d [2] aa 2f [2] ac 1a [2] 82 1a [2] bd 06 }

  condition:
    any of them
}