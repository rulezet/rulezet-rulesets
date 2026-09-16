rule TTP_XOR_WriteProcessMemory_579a {
  strings:
    $key_579a = { 00 e8 [2] 32 ca [2] 34 ff [2] 1a ff [2] 25 e3 }

  condition:
    any of them
}