rule TTP_XOR_WriteProcessMemory_c99a {
  strings:
    $key_c99a = { 9e e8 [2] ac ca [2] aa ff [2] 84 ff [2] bb e3 }

  condition:
    any of them
}