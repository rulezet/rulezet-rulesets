rule TTP_XOR_WriteProcessMemory_6c9a {
  strings:
    $key_6c9a = { 3b e8 [2] 09 ca [2] 0f ff [2] 21 ff [2] 1e e3 }

  condition:
    any of them
}