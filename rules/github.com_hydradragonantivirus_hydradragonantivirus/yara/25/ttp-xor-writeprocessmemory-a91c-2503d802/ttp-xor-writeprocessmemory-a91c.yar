rule TTP_XOR_WriteProcessMemory_a91c {
  strings:
    $key_a91c = { fe 6e [2] cc 4c [2] ca 79 [2] e4 79 [2] db 65 }

  condition:
    any of them
}