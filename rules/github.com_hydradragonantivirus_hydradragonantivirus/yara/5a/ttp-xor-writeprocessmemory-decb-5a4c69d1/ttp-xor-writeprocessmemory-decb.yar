rule TTP_XOR_WriteProcessMemory_decb {
  strings:
    $key_decb = { 89 b9 [2] bb 9b [2] bd ae [2] 93 ae [2] ac b2 }

  condition:
    any of them
}