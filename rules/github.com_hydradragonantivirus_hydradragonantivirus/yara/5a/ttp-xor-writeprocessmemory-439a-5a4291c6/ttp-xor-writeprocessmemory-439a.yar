rule TTP_XOR_WriteProcessMemory_439a {
  strings:
    $key_439a = { 14 e8 [2] 26 ca [2] 20 ff [2] 0e ff [2] 31 e3 }

  condition:
    any of them
}