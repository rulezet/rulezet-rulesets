rule TTP_XOR_WriteProcessMemory_cc07 {
  strings:
    $key_cc07 = { 9b 75 [2] a9 57 [2] af 62 [2] 81 62 [2] be 7e }

  condition:
    any of them
}