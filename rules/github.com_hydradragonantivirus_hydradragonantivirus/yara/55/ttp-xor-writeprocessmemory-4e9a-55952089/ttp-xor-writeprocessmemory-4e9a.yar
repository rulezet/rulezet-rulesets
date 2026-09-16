rule TTP_XOR_WriteProcessMemory_4e9a {
  strings:
    $key_4e9a = { 19 e8 [2] 2b ca [2] 2d ff [2] 03 ff [2] 3c e3 }

  condition:
    any of them
}