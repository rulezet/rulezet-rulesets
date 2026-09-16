rule TTP_XOR_WriteProcessMemory_019a {
  strings:
    $key_019a = { 56 e8 [2] 64 ca [2] 62 ff [2] 4c ff [2] 73 e3 }

  condition:
    any of them
}