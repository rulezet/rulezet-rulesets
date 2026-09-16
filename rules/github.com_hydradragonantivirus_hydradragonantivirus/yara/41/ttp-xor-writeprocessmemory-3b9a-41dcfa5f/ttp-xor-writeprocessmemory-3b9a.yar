rule TTP_XOR_WriteProcessMemory_3b9a {
  strings:
    $key_3b9a = { 6c e8 [2] 5e ca [2] 58 ff [2] 76 ff [2] 49 e3 }

  condition:
    any of them
}