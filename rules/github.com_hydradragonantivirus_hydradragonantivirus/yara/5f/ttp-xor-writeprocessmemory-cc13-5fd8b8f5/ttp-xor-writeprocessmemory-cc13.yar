rule TTP_XOR_WriteProcessMemory_cc13 {
  strings:
    $key_cc13 = { 9b 61 [2] a9 43 [2] af 76 [2] 81 76 [2] be 6a }

  condition:
    any of them
}