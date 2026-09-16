rule TTP_XOR_WriteProcessMemory_5f9a {
  strings:
    $key_5f9a = { 08 e8 [2] 3a ca [2] 3c ff [2] 12 ff [2] 2d e3 }

  condition:
    any of them
}