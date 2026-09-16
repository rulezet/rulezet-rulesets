rule TTP_XOR_WriteProcessMemory_4a91 {
  strings:
    $key_4a91 = { 1d e3 [2] 2f c1 [2] 29 f4 [2] 07 f4 [2] 38 e8 }

  condition:
    any of them
}