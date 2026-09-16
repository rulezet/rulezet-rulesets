rule TTP_XOR_WriteProcessMemory_0a43 {
  strings:
    $key_0a43 = { 5d 31 [2] 6f 13 [2] 69 26 [2] 47 26 [2] 78 3a }

  condition:
    any of them
}