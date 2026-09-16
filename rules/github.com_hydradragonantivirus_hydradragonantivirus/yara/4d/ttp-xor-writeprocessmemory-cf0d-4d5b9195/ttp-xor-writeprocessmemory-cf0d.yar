rule TTP_XOR_WriteProcessMemory_cf0d {
  strings:
    $key_cf0d = { 98 7f [2] aa 5d [2] ac 68 [2] 82 68 [2] bd 74 }

  condition:
    any of them
}