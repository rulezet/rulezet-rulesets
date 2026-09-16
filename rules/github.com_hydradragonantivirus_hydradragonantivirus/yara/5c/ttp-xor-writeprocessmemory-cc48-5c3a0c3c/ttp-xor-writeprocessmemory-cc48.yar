rule TTP_XOR_WriteProcessMemory_cc48 {
  strings:
    $key_cc48 = { 9b 3a [2] a9 18 [2] af 2d [2] 81 2d [2] be 31 }

  condition:
    any of them
}