rule TTP_XOR_WriteProcessMemory_4a9a {
  strings:
    $key_4a9a = { 1d e8 [2] 2f ca [2] 29 ff [2] 07 ff [2] 38 e3 }

  condition:
    any of them
}