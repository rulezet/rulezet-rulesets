rule TTP_XOR_WriteProcessMemory_cc40 {
  strings:
    $key_cc40 = { 9b 32 [2] a9 10 [2] af 25 [2] 81 25 [2] be 39 }

  condition:
    any of them
}