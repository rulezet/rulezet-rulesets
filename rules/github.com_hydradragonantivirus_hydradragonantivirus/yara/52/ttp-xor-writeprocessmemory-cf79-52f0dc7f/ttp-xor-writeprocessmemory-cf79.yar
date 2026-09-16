rule TTP_XOR_WriteProcessMemory_cf79 {
  strings:
    $key_cf79 = { 98 0b [2] aa 29 [2] ac 1c [2] 82 1c [2] bd 00 }

  condition:
    any of them
}