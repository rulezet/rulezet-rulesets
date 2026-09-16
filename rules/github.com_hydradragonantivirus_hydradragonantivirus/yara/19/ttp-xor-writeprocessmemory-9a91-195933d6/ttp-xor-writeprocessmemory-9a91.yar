rule TTP_XOR_WriteProcessMemory_9a91 {
  strings:
    $key_9a91 = { cd e3 [2] ff c1 [2] f9 f4 [2] d7 f4 [2] e8 e8 }

  condition:
    any of them
}