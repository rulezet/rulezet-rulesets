rule TTP_XOR_WriteProcessMemory_2a43 {
  strings:
    $key_2a43 = { 7d 31 [2] 4f 13 [2] 49 26 [2] 67 26 [2] 58 3a }

  condition:
    any of them
}