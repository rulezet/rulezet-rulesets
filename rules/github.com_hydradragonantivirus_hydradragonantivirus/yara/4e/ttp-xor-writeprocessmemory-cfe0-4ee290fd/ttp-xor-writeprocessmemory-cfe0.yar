rule TTP_XOR_WriteProcessMemory_cfe0 {
  strings:
    $key_cfe0 = { 98 92 [2] aa b0 [2] ac 85 [2] 82 85 [2] bd 99 }

  condition:
    any of them
}