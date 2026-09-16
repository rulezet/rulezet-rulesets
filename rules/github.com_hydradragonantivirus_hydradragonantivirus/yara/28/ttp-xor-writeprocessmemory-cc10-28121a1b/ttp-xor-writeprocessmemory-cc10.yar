rule TTP_XOR_WriteProcessMemory_cc10 {
  strings:
    $key_cc10 = { 9b 62 [2] a9 40 [2] af 75 [2] 81 75 [2] be 69 }

  condition:
    any of them
}