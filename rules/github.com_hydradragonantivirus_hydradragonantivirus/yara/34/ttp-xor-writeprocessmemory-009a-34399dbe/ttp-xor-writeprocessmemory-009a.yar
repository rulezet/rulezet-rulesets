rule TTP_XOR_WriteProcessMemory_009a {
  strings:
    $key_009a = { 57 e8 [2] 65 ca [2] 63 ff [2] 4d ff [2] 72 e3 }

  condition:
    any of them
}