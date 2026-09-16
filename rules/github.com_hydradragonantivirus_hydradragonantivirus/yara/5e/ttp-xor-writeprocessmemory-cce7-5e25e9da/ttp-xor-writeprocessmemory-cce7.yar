rule TTP_XOR_WriteProcessMemory_cce7 {
  strings:
    $key_cce7 = { 9b 95 [2] a9 b7 [2] af 82 [2] 81 82 [2] be 9e }

  condition:
    any of them
}