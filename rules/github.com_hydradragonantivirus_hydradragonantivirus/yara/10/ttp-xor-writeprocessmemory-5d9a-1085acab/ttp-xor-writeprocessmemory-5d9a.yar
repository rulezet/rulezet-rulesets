rule TTP_XOR_WriteProcessMemory_5d9a {
  strings:
    $key_5d9a = { 0a e8 [2] 38 ca [2] 3e ff [2] 10 ff [2] 2f e3 }

  condition:
    any of them
}