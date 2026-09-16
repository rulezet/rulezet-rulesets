rule TTP_XOR_WriteProcessMemory_ccd5 {
  strings:
    $key_ccd5 = { 9b a7 [2] a9 85 [2] af b0 [2] 81 b0 [2] be ac }

  condition:
    any of them
}