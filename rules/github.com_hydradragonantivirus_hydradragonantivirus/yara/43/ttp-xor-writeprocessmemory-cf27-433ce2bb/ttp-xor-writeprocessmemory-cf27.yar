rule TTP_XOR_WriteProcessMemory_cf27 {
  strings:
    $key_cf27 = { 98 55 [2] aa 77 [2] ac 42 [2] 82 42 [2] bd 5e }

  condition:
    any of them
}