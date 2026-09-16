rule TTP_XOR_WriteProcessMemory_cfb1 {
  strings:
    $key_cfb1 = { 98 c3 [2] aa e1 [2] ac d4 [2] 82 d4 [2] bd c8 }

  condition:
    any of them
}