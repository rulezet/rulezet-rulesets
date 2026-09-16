rule TTP_XOR_WriteProcessMemory_619a {
  strings:
    $key_619a = { 36 e8 [2] 04 ca [2] 02 ff [2] 2c ff [2] 13 e3 }

  condition:
    any of them
}