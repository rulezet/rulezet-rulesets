rule TTP_XOR_WriteProcessMemory_0ea6 {
  strings:
    $key_0ea6 = { 59 d4 [2] 6b f6 [2] 6d c3 [2] 43 c3 [2] 7c df }

  condition:
    any of them
}