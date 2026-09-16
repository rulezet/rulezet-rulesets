rule TTP_XOR_WriteProcessMemory_7e9a {
  strings:
    $key_7e9a = { 29 e8 [2] 1b ca [2] 1d ff [2] 33 ff [2] 0c e3 }

  condition:
    any of them
}