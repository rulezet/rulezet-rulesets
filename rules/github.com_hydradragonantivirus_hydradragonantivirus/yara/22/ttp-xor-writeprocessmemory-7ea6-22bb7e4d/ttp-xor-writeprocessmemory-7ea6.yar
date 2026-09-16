rule TTP_XOR_WriteProcessMemory_7ea6 {
  strings:
    $key_7ea6 = { 29 d4 [2] 1b f6 [2] 1d c3 [2] 33 c3 [2] 0c df }

  condition:
    any of them
}