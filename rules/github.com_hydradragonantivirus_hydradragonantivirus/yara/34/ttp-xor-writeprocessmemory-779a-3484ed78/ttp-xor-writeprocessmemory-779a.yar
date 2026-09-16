rule TTP_XOR_WriteProcessMemory_779a {
  strings:
    $key_779a = { 20 e8 [2] 12 ca [2] 14 ff [2] 3a ff [2] 05 e3 }

  condition:
    any of them
}