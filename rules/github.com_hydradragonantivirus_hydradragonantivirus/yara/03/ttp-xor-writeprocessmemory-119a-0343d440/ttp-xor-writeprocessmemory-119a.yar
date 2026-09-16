rule TTP_XOR_WriteProcessMemory_119a {
  strings:
    $key_119a = { 46 e8 [2] 74 ca [2] 72 ff [2] 5c ff [2] 63 e3 }

  condition:
    any of them
}