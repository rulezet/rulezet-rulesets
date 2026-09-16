rule TTP_XOR_WriteProcessMemory_cf07 {
  strings:
    $key_cf07 = { 98 75 [2] aa 57 [2] ac 62 [2] 82 62 [2] bd 7e }

  condition:
    any of them
}