rule TTP_XOR_WriteProcessMemory_3a43 {
  strings:
    $key_3a43 = { 6d 31 [2] 5f 13 [2] 59 26 [2] 77 26 [2] 48 3a }

  condition:
    any of them
}