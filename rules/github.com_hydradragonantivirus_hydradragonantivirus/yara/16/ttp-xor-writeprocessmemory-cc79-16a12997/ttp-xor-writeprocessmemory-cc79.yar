rule TTP_XOR_WriteProcessMemory_cc79 {
  strings:
    $key_cc79 = { 9b 0b [2] a9 29 [2] af 1c [2] 81 1c [2] be 00 }

  condition:
    any of them
}