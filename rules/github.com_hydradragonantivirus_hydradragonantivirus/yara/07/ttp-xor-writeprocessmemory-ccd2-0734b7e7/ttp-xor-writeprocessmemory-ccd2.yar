rule TTP_XOR_WriteProcessMemory_ccd2 {
  strings:
    $key_ccd2 = { 9b a0 [2] a9 82 [2] af b7 [2] 81 b7 [2] be ab }

  condition:
    any of them
}