rule TTP_XOR_WriteProcessMemory_cf2f {
  strings:
    $key_cf2f = { 98 5d [2] aa 7f [2] ac 4a [2] 82 4a [2] bd 56 }

  condition:
    any of them
}