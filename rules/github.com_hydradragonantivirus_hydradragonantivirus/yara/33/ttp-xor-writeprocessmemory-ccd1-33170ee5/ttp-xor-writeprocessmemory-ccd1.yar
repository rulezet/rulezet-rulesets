rule TTP_XOR_WriteProcessMemory_ccd1 {
  strings:
    $key_ccd1 = { 9b a3 [2] a9 81 [2] af b4 [2] 81 b4 [2] be a8 }

  condition:
    any of them
}