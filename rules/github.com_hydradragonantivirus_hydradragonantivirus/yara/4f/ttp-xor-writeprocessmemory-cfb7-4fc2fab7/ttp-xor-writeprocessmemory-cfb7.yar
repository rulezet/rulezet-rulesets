rule TTP_XOR_WriteProcessMemory_cfb7 {
  strings:
    $key_cfb7 = { 98 c5 [2] aa e7 [2] ac d2 [2] 82 d2 [2] bd ce }

  condition:
    any of them
}