rule TTP_XOR_WriteProcessMemory_759a {
  strings:
    $key_759a = { 22 e8 [2] 10 ca [2] 16 ff [2] 38 ff [2] 07 e3 }

  condition:
    any of them
}