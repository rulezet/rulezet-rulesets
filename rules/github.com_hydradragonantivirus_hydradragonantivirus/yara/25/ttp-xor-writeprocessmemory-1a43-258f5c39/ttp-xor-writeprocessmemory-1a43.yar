rule TTP_XOR_WriteProcessMemory_1a43 {
  strings:
    $key_1a43 = { 4d 31 [2] 7f 13 [2] 79 26 [2] 57 26 [2] 68 3a }

  condition:
    any of them
}