rule TTP_XOR_WriteProcessMemory_cf57 {
  strings:
    $key_cf57 = { 98 25 [2] aa 07 [2] ac 32 [2] 82 32 [2] bd 2e }

  condition:
    any of them
}