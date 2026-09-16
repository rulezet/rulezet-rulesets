rule TTP_XOR_WriteProcessMemory_cf2a {
  strings:
    $key_cf2a = { 98 58 [2] aa 7a [2] ac 4f [2] 82 4f [2] bd 53 }

  condition:
    any of them
}