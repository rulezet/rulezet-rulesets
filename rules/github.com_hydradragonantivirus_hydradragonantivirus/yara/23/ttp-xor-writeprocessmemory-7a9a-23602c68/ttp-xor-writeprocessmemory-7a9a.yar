rule TTP_XOR_WriteProcessMemory_7a9a {
  strings:
    $key_7a9a = { 2d e8 [2] 1f ca [2] 19 ff [2] 37 ff [2] 08 e3 }

  condition:
    any of them
}