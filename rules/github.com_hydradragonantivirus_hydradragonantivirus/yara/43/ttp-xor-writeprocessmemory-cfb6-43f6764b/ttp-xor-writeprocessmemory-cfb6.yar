rule TTP_XOR_WriteProcessMemory_cfb6 {
  strings:
    $key_cfb6 = { 98 c4 [2] aa e6 [2] ac d3 [2] 82 d3 [2] bd cf }

  condition:
    any of them
}