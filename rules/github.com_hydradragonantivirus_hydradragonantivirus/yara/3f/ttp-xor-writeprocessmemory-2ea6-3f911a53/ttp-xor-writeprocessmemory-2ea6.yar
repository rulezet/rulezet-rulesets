rule TTP_XOR_WriteProcessMemory_2ea6 {
  strings:
    $key_2ea6 = { 79 d4 [2] 4b f6 [2] 4d c3 [2] 63 c3 [2] 5c df }

  condition:
    any of them
}