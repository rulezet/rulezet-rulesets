rule TTP_XOR_WriteProcessMemory_1d9a {
  strings:
    $key_1d9a = { 4a e8 [2] 78 ca [2] 7e ff [2] 50 ff [2] 6f e3 }

  condition:
    any of them
}