rule TTP_XOR_WriteProcessMemory_0c9a {
  strings:
    $key_0c9a = { 5b e8 [2] 69 ca [2] 6f ff [2] 41 ff [2] 7e e3 }

  condition:
    any of them
}