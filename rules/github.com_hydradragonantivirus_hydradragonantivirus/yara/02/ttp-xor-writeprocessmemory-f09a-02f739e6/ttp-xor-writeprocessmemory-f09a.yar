rule TTP_XOR_WriteProcessMemory_f09a {
  strings:
    $key_f09a = { a7 e8 [2] 95 ca [2] 93 ff [2] bd ff [2] 82 e3 }

  condition:
    any of them
}