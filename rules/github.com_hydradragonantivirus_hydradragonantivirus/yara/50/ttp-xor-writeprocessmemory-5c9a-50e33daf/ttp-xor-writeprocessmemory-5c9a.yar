rule TTP_XOR_WriteProcessMemory_5c9a {
  strings:
    $key_5c9a = { 0b e8 [2] 39 ca [2] 3f ff [2] 11 ff [2] 2e e3 }

  condition:
    any of them
}