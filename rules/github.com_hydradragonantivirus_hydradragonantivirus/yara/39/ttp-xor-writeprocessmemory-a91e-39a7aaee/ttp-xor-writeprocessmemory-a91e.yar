rule TTP_XOR_WriteProcessMemory_a91e {
  strings:
    $key_a91e = { fe 6c [2] cc 4e [2] ca 7b [2] e4 7b [2] db 67 }

  condition:
    any of them
}