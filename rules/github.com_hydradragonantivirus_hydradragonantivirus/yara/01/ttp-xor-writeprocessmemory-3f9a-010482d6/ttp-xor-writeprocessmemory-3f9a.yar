rule TTP_XOR_WriteProcessMemory_3f9a {
  strings:
    $key_3f9a = { 68 e8 [2] 5a ca [2] 5c ff [2] 72 ff [2] 4d e3 }

  condition:
    any of them
}