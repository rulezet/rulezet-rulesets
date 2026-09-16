rule TTP_XOR_WriteProcessMemory_4c9a {
  strings:
    $key_4c9a = { 1b e8 [2] 29 ca [2] 2f ff [2] 01 ff [2] 3e e3 }

  condition:
    any of them
}