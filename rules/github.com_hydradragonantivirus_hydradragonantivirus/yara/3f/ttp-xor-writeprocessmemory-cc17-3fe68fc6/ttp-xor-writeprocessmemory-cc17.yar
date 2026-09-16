rule TTP_XOR_WriteProcessMemory_cc17 {
  strings:
    $key_cc17 = { 9b 65 [2] a9 47 [2] af 72 [2] 81 72 [2] be 6e }

  condition:
    any of them
}