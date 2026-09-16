rule TTP_XOR_WriteProcessMemory_179a {
  strings:
    $key_179a = { 40 e8 [2] 72 ca [2] 74 ff [2] 5a ff [2] 65 e3 }

  condition:
    any of them
}