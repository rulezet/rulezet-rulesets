rule TTP_XOR_WriteProcessMemory_cc11 {
  strings:
    $key_cc11 = { 9b 63 [2] a9 41 [2] af 74 [2] 81 74 [2] be 68 }

  condition:
    any of them
}