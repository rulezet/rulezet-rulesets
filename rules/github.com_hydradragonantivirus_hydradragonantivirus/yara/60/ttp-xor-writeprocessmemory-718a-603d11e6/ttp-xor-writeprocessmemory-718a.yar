rule TTP_XOR_WriteProcessMemory_718a {
  strings:
    $key_718a = { 26 f8 [2] 14 da [2] 12 ef [2] 3c ef [2] 03 f3 }

  condition:
    any of them
}