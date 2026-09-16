rule TTP_XOR_WriteProcessMemory_cf1f {
  strings:
    $key_cf1f = { 98 6d [2] aa 4f [2] ac 7a [2] 82 7a [2] bd 66 }

  condition:
    any of them
}