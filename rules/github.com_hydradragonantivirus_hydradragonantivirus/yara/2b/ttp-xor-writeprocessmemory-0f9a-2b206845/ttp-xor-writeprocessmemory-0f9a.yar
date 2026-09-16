rule TTP_XOR_WriteProcessMemory_0f9a {
  strings:
    $key_0f9a = { 58 e8 [2] 6a ca [2] 6c ff [2] 42 ff [2] 7d e3 }

  condition:
    any of them
}