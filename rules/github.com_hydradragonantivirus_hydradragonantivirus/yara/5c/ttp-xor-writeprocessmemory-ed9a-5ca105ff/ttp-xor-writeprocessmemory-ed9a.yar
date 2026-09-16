rule TTP_XOR_WriteProcessMemory_ed9a {
  strings:
    $key_ed9a = { ba e8 [2] 88 ca [2] 8e ff [2] a0 ff [2] 9f e3 }

  condition:
    any of them
}