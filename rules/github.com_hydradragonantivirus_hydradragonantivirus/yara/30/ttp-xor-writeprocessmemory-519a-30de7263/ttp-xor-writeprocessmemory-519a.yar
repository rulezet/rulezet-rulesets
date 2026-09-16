rule TTP_XOR_WriteProcessMemory_519a {
  strings:
    $key_519a = { 06 e8 [2] 34 ca [2] 32 ff [2] 1c ff [2] 23 e3 }

  condition:
    any of them
}