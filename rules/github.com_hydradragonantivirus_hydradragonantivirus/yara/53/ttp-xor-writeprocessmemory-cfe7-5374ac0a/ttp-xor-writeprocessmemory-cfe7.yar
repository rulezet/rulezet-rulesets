rule TTP_XOR_WriteProcessMemory_cfe7 {
  strings:
    $key_cfe7 = { 98 95 [2] aa b7 [2] ac 82 [2] 82 82 [2] bd 9e }

  condition:
    any of them
}