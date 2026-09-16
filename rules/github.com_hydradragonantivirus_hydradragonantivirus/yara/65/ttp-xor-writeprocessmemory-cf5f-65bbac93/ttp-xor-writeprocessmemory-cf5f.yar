rule TTP_XOR_WriteProcessMemory_cf5f {
  strings:
    $key_cf5f = { 98 2d [2] aa 0f [2] ac 3a [2] 82 3a [2] bd 26 }

  condition:
    any of them
}