rule TTP_XOR_WriteProcessMemory_1ea6 {
  strings:
    $key_1ea6 = { 49 d4 [2] 7b f6 [2] 7d c3 [2] 53 c3 [2] 6c df }

  condition:
    any of them
}