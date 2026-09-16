rule TTP_XOR_WriteProcessMemory_f69a {
  strings:
    $key_f69a = { a1 e8 [2] 93 ca [2] 95 ff [2] bb ff [2] 84 e3 }

  condition:
    any of them
}