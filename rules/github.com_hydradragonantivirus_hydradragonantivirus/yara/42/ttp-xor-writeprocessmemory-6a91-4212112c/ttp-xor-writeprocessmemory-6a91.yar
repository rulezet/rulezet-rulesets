rule TTP_XOR_WriteProcessMemory_6a91 {
  strings:
    $key_6a91 = { 3d e3 [2] 0f c1 [2] 09 f4 [2] 27 f4 [2] 18 e8 }

  condition:
    any of them
}