rule TTP_XOR_WriteProcessMemory_cc73 {
  strings:
    $key_cc73 = { 9b 01 [2] a9 23 [2] af 16 [2] 81 16 [2] be 0a }

  condition:
    any of them
}