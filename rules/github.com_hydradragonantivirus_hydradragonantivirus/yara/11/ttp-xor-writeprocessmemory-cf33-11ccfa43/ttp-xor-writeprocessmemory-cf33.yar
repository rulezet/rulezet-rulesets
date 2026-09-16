rule TTP_XOR_WriteProcessMemory_cf33 {
  strings:
    $key_cf33 = { 98 41 [2] aa 63 [2] ac 56 [2] 82 56 [2] bd 4a }

  condition:
    any of them
}