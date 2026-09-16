rule TTP_XOR_WriteProcessMemory_cf09 {
  strings:
    $key_cf09 = { 98 7b [2] aa 59 [2] ac 6c [2] 82 6c [2] bd 70 }

  condition:
    any of them
}