rule TTP_XOR_WriteProcessMemory_cf0c {
  strings:
    $key_cf0c = { 98 7e [2] aa 5c [2] ac 69 [2] 82 69 [2] bd 75 }

  condition:
    any of them
}