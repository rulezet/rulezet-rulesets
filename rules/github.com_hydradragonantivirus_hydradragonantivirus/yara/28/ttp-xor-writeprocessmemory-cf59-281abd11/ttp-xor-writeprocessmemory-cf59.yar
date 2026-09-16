rule TTP_XOR_WriteProcessMemory_cf59 {
  strings:
    $key_cf59 = { 98 2b [2] aa 09 [2] ac 3c [2] 82 3c [2] bd 20 }

  condition:
    any of them
}