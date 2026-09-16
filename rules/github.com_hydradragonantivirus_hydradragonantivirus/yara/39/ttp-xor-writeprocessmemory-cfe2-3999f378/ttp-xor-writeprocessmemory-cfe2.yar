rule TTP_XOR_WriteProcessMemory_cfe2 {
  strings:
    $key_cfe2 = { 98 90 [2] aa b2 [2] ac 87 [2] 82 87 [2] bd 9b }

  condition:
    any of them
}