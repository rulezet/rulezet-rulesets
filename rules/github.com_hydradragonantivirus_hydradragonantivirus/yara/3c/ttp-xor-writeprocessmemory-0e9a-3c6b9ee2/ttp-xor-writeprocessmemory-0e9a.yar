rule TTP_XOR_WriteProcessMemory_0e9a {
  strings:
    $key_0e9a = { 59 e8 [2] 6b ca [2] 6d ff [2] 43 ff [2] 7c e3 }

  condition:
    any of them
}