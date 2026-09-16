rule TTP_XOR_WriteProcessMemory_639a {
  strings:
    $key_639a = { 34 e8 [2] 06 ca [2] 00 ff [2] 2e ff [2] 11 e3 }

  condition:
    any of them
}