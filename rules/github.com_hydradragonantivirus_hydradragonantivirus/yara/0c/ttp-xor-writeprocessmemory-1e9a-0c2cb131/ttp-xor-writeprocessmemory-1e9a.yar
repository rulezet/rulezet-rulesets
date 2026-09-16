rule TTP_XOR_WriteProcessMemory_1e9a {
  strings:
    $key_1e9a = { 49 e8 [2] 7b ca [2] 7d ff [2] 53 ff [2] 6c e3 }

  condition:
    any of them
}