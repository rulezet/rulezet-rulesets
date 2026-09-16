rule TTP_XOR_WriteProcessMemory_ccd0 {
  strings:
    $key_ccd0 = { 9b a2 [2] a9 80 [2] af b5 [2] 81 b5 [2] be a9 }

  condition:
    any of them
}