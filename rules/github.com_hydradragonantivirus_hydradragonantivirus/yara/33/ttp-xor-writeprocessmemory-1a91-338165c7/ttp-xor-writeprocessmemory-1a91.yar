rule TTP_XOR_WriteProcessMemory_1a91 {
  strings:
    $key_1a91 = { 4d e3 [2] 7f c1 [2] 79 f4 [2] 57 f4 [2] 68 e8 }

  condition:
    any of them
}