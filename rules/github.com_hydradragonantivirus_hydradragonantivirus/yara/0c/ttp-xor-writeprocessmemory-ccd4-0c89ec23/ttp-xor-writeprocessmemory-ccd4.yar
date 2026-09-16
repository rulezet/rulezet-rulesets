rule TTP_XOR_WriteProcessMemory_ccd4 {
  strings:
    $key_ccd4 = { 9b a6 [2] a9 84 [2] af b1 [2] 81 b1 [2] be ad }

  condition:
    any of them
}