rule TTP_XOR_WriteProcessMemory_cff7 {
  strings:
    $key_cff7 = { 98 85 [2] aa a7 [2] ac 92 [2] 82 92 [2] bd 8e }

  condition:
    any of them
}