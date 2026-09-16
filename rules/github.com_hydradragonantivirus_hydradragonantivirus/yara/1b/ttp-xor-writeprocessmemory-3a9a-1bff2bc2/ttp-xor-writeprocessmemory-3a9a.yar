rule TTP_XOR_WriteProcessMemory_3a9a {
  strings:
    $key_3a9a = { 6d e8 [2] 5f ca [2] 59 ff [2] 77 ff [2] 48 e3 }

  condition:
    any of them
}