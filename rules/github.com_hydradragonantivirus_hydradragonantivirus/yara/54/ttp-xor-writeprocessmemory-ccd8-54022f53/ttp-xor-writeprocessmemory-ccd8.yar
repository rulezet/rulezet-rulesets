rule TTP_XOR_WriteProcessMemory_ccd8 {
  strings:
    $key_ccd8 = { 9b aa [2] a9 88 [2] af bd [2] 81 bd [2] be a1 }

  condition:
    any of them
}